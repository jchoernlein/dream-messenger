from asyncio import run
import base64
from contextlib import asynccontextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from client import (
    Conversation,
    ConversationState,
    Message,
    SkippedKey,
    TransmittedMessage,
    UserInfo,
    ck_kdf,
    rk_kdf,
)


@asynccontextmanager
async def temp_dbs(*names):
    with TemporaryDirectory(prefix="dream-demo-") as directory:
        dbs = []
        try:
            for name in names:
                path = Path(directory) / f"{name}.db"
                db = create_async_engine(f"sqlite+aiosqlite:///{path}")
                dbs.append(db)
                async with db.begin() as conn:
                    await conn.run_sync(SQLModel.metadata.create_all)

                async with AsyncSession(db) as session:
                    session.add(UserInfo(
                        name=name,
                        identity_key=X25519PrivateKey.generate().private_bytes_raw(),
                        authentication_key="dummy"
                    ))
                    await session.commit()

            yield dbs
        finally:
            for db in dbs:
                await db.dispose()

async def get_key(engine):
    async with AsyncSession(engine) as session:
        user = (await session.exec(select(UserInfo))).one()
        return X25519PrivateKey.from_private_bytes(user.identity_key)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def public_dh(message: TransmittedMessage) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(base64.b64decode(message.header.dh))


def message_keys(chain_key: bytes, count: int) -> list[bytes]:
    keys = []
    for _ in range(count):
        chain_key, key = ck_kdf(chain_key)
        keys.append(key)
    return keys


async def snapshot(conversation: Conversation) -> ConversationState:
    async with AsyncSession(conversation.engine) as session:
        state = await session.get(ConversationState, conversation.conversation_id)
        if state is None:
            raise RuntimeError("Demo conversation is missing")
        return state


async def skipped_keys(conversation: Conversation) -> list[bytes]:
    async with AsyncSession(conversation.engine) as session:
        result = await session.exec(select(SkippedKey).where(
            SkippedKey.conversation_id == conversation.conversation_id
        ))
        return [key.mk for key in result.all()]


def report(
    title: str,
    captures: dict[str, TransmittedMessage],
    keys: list[bytes],
    associated_data: bytes,
    expected: set[str],
) -> None:
    """Try only stolen/derived keys against real captured ciphertexts."""
    print(f"\n{title}")
    readable = set()
    for label, message in captures.items():
        plaintext = None
        for key in keys:
            try:
                plaintext = AESGCMSIV(key).decrypt(
                    bytes(12),
                    base64.b64decode(message.ciphertext),
                    associated_data + message.header.encode(),
                ).decode()
            except InvalidTag:
                continue
            break
        if plaintext is None:
            print(f"  BLOCKED {label}")
        else:
            check(plaintext == label, f"Unexpected plaintext for {label}: {plaintext!r}")
            readable.add(label)
            print(f"  READ    {label}: {plaintext!r}")
    check(readable == expected, f"{title}: expected {expected}, got {readable}")


async def start_chat(alice_engine, bob_engine):
    alice_key = await get_key(alice_engine)
    bob_key = await get_key(bob_engine)
    alice = await Conversation.create(
        alice_engine, alice_key, "Bob", bob_key.public_key()
    )
    first = await alice.send_message("A0: initial message")
    bob = await Conversation.create(
        bob_engine, bob_key, "Alice", alice_key.public_key(), public_dh(first)
    )
    check(await bob.receive_message(first) == "A0: initial message", "Bootstrap failed")
    return alice, bob, first


async def compromise_timeline() -> None:
    async with temp_dbs("Alice", "Bob") as (alice_engine, bob_engine):
        alice, bob, first = await start_chat(alice_engine, bob_engine)
        captures = {"A0: initial message": first}

        async def deliver(sender, receiver, label):
            message = await sender.send_message(label)
            captures[label] = message
            check(await receiver.receive_message(message) == label, f"Delivery: {label}")
            return message

        await deliver(alice, bob, "A1: before compromise")
        stolen = await snapshot(alice)
        future_keys = message_keys(stolen.chain_key_sent, 2)
        await deliver(alice, bob, "A2: after compromise")
        await deliver(alice, bob, "A3: same chain, still exposed")
        reply = await deliver(bob, alice, "B0: first DH reply")
        await deliver(alice, bob, "A4: fresh local DH, recovered")
        await deliver(bob, alice, "B1: next DH reply, recovered")

        report(
            "1. One stolen message key (A2 only)",
            captures, future_keys[:1], stolen.AD, {"A2: after compromise"},
        )
        report(
            "2. Alice's sending-chain key stolen after A1 (no backward derivation)",
            captures, future_keys, stolen.AD,
            {"A2: after compromise", "A3: same chain, still exposed"},
        )

        # The old private DH still unlocks Bob's first fresh-DH receiving chain.
        _, receiving_chain = rk_kdf(
            stolen.root_key,
            X25519PrivateKey.from_private_bytes(stolen.dh_sent).exchange(public_dh(reply)),
        )
        report(
            "3. Alice's full ratchet-state snapshot after A1; passive attacker thereafter",
            captures, future_keys + message_keys(receiving_chain, 1), stolen.AD,
            {"A2: after compromise", "A3: same chain, still exposed", "B0: first DH reply"},
        )

        bob_identity = await get_key(bob_engine)
        alice_identity = await get_key(alice_engine)
        initial_root = bob_identity.exchange(alice_identity.public_key())
        _, initial_chain = rk_kdf(initial_root, bob_identity.exchange(public_dh(first)))
        report(
            "4. Bob's long-term identity key stolen later (bootstrap limitation)",
            captures, message_keys(initial_chain, 4), stolen.AD,
            {
                "A0: initial message", "A1: before compromise",
                "A2: after compromise", "A3: same chain, still exposed",
            },
        )

        async with AsyncSession(alice_engine) as session:
            history = (await session.exec(select(Message).where(
                Message.conversation_id == alice.conversation_id
            ))).all()
        readable = {message.content for message in history}
        check(readable == set(captures), "Database theft did not expose expected history")
        print("\n5. Full Alice database theft after recovery (plaintext history, not key recovery)")
        for label in captures:
            print(f"  READ    {label}: {label!r}")


async def skipped_message_demo() -> None:
    async with temp_dbs("Alice", "Bob") as (alice_engine, bob_engine):
        alice, bob, _ = await start_chat(alice_engine, bob_engine)
        captures = {}
        for label in ("S1: delayed", "S2: delayed", "S3: delivered first"):
            captures[label] = await alice.send_message(label)
        check(
            await bob.receive_message(captures["S3: delivered first"]) == "S3: delivered first",
            "Out-of-order delivery failed",
        )
        state = await snapshot(bob)
        keys = await skipped_keys(bob)
        check(len(keys) == 2, "Expected two retained skipped keys")
        report(
            "6. Bob's skipped-key cache stolen after S3 (delayed past messages exposed)",
            captures, keys, state.AD, {"S1: delayed", "S2: delayed"},
        )
        for label in ("S2: delayed", "S1: delayed"):
            check(await bob.receive_message(captures[label]) == label, "Skipped delivery failed")
        check(not await skipped_keys(bob), "Consumed skipped keys were not removed")
        advanced = await snapshot(bob)
        if advanced.chain_key_received is None:
            raise RuntimeError("Bob's receiving chain was not initialized")
        report(
            "   Later snapshot: cache consumed, receiving chain advanced beyond S3",
            captures, message_keys(advanced.chain_key_received, 1), advanced.AD, set(),
        )


async def integrity_demo() -> None:
    async with temp_dbs("Alice", "Bob") as (alice_engine, bob_engine):
        alice, bob, _ = await start_chat(alice_engine, bob_engine)
        # Leave a gap so failed authentication also exercises skipped-key rollback.
        delayed = await alice.send_message("I0: delayed")
        original = await alice.send_message("I1: authentic")
        before = (await snapshot(bob)).model_dump()
        variants = {}
        altered = original.model_copy(deep=True)
        ciphertext = bytearray(base64.b64decode(altered.ciphertext))
        ciphertext[0] ^= 1
        altered.ciphertext = base64.b64encode(ciphertext).decode()
        variants["ciphertext modification"] = altered
        altered = original.model_copy(deep=True)
        altered.header.n += 1
        variants["message-number modification"] = altered
        altered = original.model_copy(deep=True)
        altered.header.dh = base64.b64encode(
            X25519PrivateKey.generate().public_key().public_bytes_raw()
        ).decode()
        variants["DH-header modification"] = altered
        altered = original.model_copy(deep=True)
        altered.header.pn += 1
        variants["previous-chain-length modification"] = altered
        altered = original.model_copy(deep=True)
        altered.header.timestamp = altered.header.timestamp.replace(
            year=altered.header.timestamp.year + 1
        )
        variants["timestamp modification"] = altered

        print("\n7. Active tampering, replay, and bounded out-of-order delivery")
        for label, message in variants.items():
            try:
                await bob.receive_message(message)
            except InvalidTag:
                print(f"  REJECTED {label}")
            else:
                raise AssertionError(f"Accepted {label}")
            check((await snapshot(bob)).model_dump() == before, f"{label} changed state")
            check(not await skipped_keys(bob), f"{label} persisted skipped keys")

        excessive = original.model_copy(deep=True)
        excessive.header.n = before["num_received"] + 1001
        try:
            await bob.receive_message(excessive)
        except ValueError as error:
            check(str(error) == "Max skips exceeded.", f"Unexpected error: {error}")
            print("  REJECTED gap beyond 1,000 skipped keys")
        else:
            raise AssertionError("Accepted excessive skip count")
        check((await snapshot(bob)).model_dump() == before, "Skip rejection changed state")

        check(await bob.receive_message(original) == "I1: authentic", "Valid retry failed")
        check(await bob.receive_message(delayed) == "I0: delayed", "Delayed message lost")
        for message in (original, delayed):
            before = (await snapshot(bob)).model_dump()
            try:
                await bob.receive_message(message)
            except InvalidTag:
                print(f"  REJECTED replay of message {message.header.n}")
            else:
                raise AssertionError("Accepted replay")
            check((await snapshot(bob)).model_dump() == before, "Replay changed state")
        async with AsyncSession(bob_engine) as session:
            history = (await session.exec(select(Message))).all()
        check(len(history) == 3, "Rejected traffic was persisted as plaintext")
        print("  PASS     authentic retry and delayed delivery still work")

        sender = await snapshot(alice)
        boundary = original.model_copy(deep=True)
        boundary.header.n = (await snapshot(bob)).num_received + 1000
        boundary_key = message_keys(sender.chain_key_sent, 1001)[-1]
        boundary.ciphertext = base64.b64encode(AESGCMSIV(boundary_key).encrypt(
            bytes(12), b"I2: exactly 1,000 skipped keys",
            sender.AD + boundary.header.encode(),
        )).decode()
        check(
            await bob.receive_message(boundary) == "I2: exactly 1,000 skipped keys",
            "Exact skip-limit boundary was rejected",
        )
        check(len(await skipped_keys(bob)) == 1000, "Incorrect skipped-key limit")
        print("  PASS     exactly 1,000 skipped keys are permitted")


async def identity_substitution_demo() -> None:
    async with temp_dbs("Alice", "Bob", "Mallory") as (alice_db, bob_db, mallory_db):
        alice_key = await get_key(alice_db)
        bob_key = await get_key(bob_db)
        mallory_key = await get_key(mallory_db)

        # Model a directory returning Mallory's public identity for each peer.
        alice = await Conversation.create(alice_db, alice_key, "Bob", mallory_key.public_key())
        outgoing = await alice.send_message("M0: Alice to Bob via Mallory")
        mallory_as_bob = await Conversation.create(
            mallory_db, mallory_key, "Alice", alice_key.public_key(), public_dh(outgoing)
        )
        plaintext = await mallory_as_bob.receive_message(outgoing)
        check(plaintext == "M0: Alice to Bob via Mallory", "Mallory could not read Alice")
        print("\n8. Unverified identity substitution (two attacker-terminated sessions)")
        print(f"  READ    {plaintext!r}")

        mallory_as_alice = await Conversation.create(
            mallory_db, mallory_key, "Bob", bob_key.public_key()
        )
        forwarded = await mallory_as_alice.send_message(plaintext)
        bob = await Conversation.create(
            bob_db, bob_key, "Alice", mallory_key.public_key(), public_dh(forwarded)
        )
        check(await bob.receive_message(forwarded) == plaintext, "Forwarding to Bob failed")
        reply = await bob.send_message("M1: Bob to Alice via Mallory")
        plaintext = await mallory_as_alice.receive_message(reply)
        check(plaintext == "M1: Bob to Alice via Mallory", "Mallory could not read Bob")
        print(f"  READ    {plaintext!r}")
        forwarded = await mallory_as_bob.send_message(plaintext)
        check(await alice.receive_message(forwarded) == plaintext, "Forwarding to Alice failed")
        print("  PASS     both peers receive plaintext despite Mallory reading both directions")


async def main() -> None:
    print("Double Ratchet adversarial demo: READ = authenticated plaintext recovered")
    print("Key-only theft excludes stored plaintext; snapshots are one-time, not ongoing access.")
    await compromise_timeline()
    await skipped_message_demo()
    await integrity_demo()
    await identity_substitution_demo()
    print("\nAll 8 scenarios passed their expected outcomes (including known vulnerabilities).")


if __name__ == "__main__":
    run(main())
