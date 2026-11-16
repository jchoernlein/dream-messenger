import base64
from contextlib import asynccontextmanager
import json
import os
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body, Header
import jwt
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
from sqlmodel import SQLModel, Field, select
from sqlmodel.ext.asyncio.session import AsyncSession


class DreamServer(FastAPI):

    JWT_SECRET = os.getenv("JWT_SECRET", "fear_is_the_mind_killer")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    POSTGRES_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/dream_messenger")

    class User(SQLModel, table=True):
        username: str = Field(primary_key=True)
        identity: str

    def __init__(self, *args, **kwargs):
        self.open_websockets: dict[tuple[str, str], WebSocket] = {}
        self.redis: redis.Redis = None
        self.pg: AsyncEngine  = None
        super().__init__(*args, **kwargs, lifespan=DreamServer.lifespan)

    @asynccontextmanager
    @staticmethod
    async def lifespan(app: DreamServer):
        """Lifespan context manager for the DreamServer app."""

        app.redis = await redis.from_url(DreamServer.REDIS_URL)
        async_url = DreamServer.POSTGRES_URL.replace(
            "postgresql://", 
            "postgresql+asyncpg://"
        )
        app.pg = create_async_engine(async_url, echo=True)
        async with app.pg.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

        yield

        await app.redis.close()
        await app.pg.dispose()


app = DreamServer()

@app.post("/register", status_code=201)
async def register(
    username: Annotated[str, Body(regex=r"^[a-zA-Z0-9_]+$")],   # Alphanumeric usernames with underscores only
    identity: Annotated[str, Body(regex=r"^[A-Za-z0-9+/=]+$")]  # Base64-encoded X25519 public key
):
    async with AsyncSession(app.pg) as session:
        # Check if username is already registered
        statement = select(DreamServer.User).where(DreamServer.User.username == username)
        result = await session.exec(statement)
        existing_user = result.one_or_none()
        
        if existing_user:
            raise Exception("User already registered")

        # Validate the identity as a proper X25519 public key
        try:
            id_bytes = base64.b64decode(identity)
            X25519PublicKey.from_public_bytes(id_bytes)
        except ValueError:
            raise Exception("Invalid identity")

        # Add the new user to the database
        new_user = DreamServer.User(username=username, identity=identity)
        session.add(new_user)
        await session.commit()

        # Return an authentication token for the newly registered user
        return jwt.encode({"username": username}, app.JWT_SECRET, algorithm="HS256")

@app.get("/{recipient}/id")
async def get_recipient_id(recipient: str):
    async with AsyncSession(app.pg) as session:
        statement = select(DreamServer.User).where(DreamServer.User.username == recipient)
        result = await session.exec(statement)
        user = result.one_or_none()
        
        if not user:
            raise Exception("User not found")
        
        return user.identity

@app.websocket("/{recipient}/chat")
async def chat_endpoint(
    recipient: str,
    token: Annotated[str, Header()],
    websocket: WebSocket
):    
    # Get the sender's username from the token
    token = jwt.decode(token, app.JWT_SECRET, algorithms=["HS256"])
    sender = token["username"]

    if sender == recipient:
        raise Exception("Cannot chat with yourself")

    # Close existing WebSocket connection if it exists
    if (sender, recipient) in app.open_websockets:
        raise Exception("WebSocket connection already exists")
    
    # Accept the new WebSocket and store it
    await websocket.accept()
    app.open_websockets[sender, recipient] = websocket

    # Flush any pending messages for the sender from Redis
    pending_key = f"pending_messages:{sender}:{recipient}"
    pending_messages = await app.redis.lrange(pending_key, 0, -1)
    for message_json in pending_messages:
        message = json.loads(message_json)
        await websocket.send_json(message)
    await app.redis.delete(pending_key)

    try:
        while True:
            # Listen for incoming messages from the sender
            data = await websocket.receive_json()

            # Forward the message to the recipient if they are connected,
            # otherwise store it as a pending message in Redis
            if (recipient, sender) in app.open_websockets:
                await app.open_websockets[recipient, sender].send_json(data)
            else:
                pending_key = f"pending_messages:{recipient}:{sender}"
                await app.redis.rpush(pending_key, json.dumps(data))
    except WebSocketDisconnect:
        if (sender, recipient) in app.open_websockets:
            del app.open_websockets[sender, recipient]
