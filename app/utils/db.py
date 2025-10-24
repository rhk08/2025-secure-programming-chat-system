# db.py
import os
import json
import base64
import secrets
from typing import Optional, Dict, Any, List

import aiosqlite
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))


class ChatDB:
    """
    Minimal persistent layer for:
      - users(user_id, pubkey, privkey_store, pake_password, meta, version)
      - groups(group_id, creator_id, created_at, meta, version)
      - group_members(group_id, member_id, role, wrapped_key, added_at)

    Notes:
      - Group clear keys are NEVER stored in DB. They live in memory only.
      - On cold start (no in-memory key), we rotate (bump version) to start a new epoch.
    """

    def __init__(self, path: str = "chat.db"):
        self.path = path
        self._group_keys: Dict[str, bytes] = {}  # group_id -> 32-byte key

    async def init(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        async with aiosqlite.connect(self.path) as db:
            await db.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,          -- base64url(PEM)
                    privkey_store TEXT NOT NULL,   -- encrypted blob placeholder
                    pake_password TEXT NOT NULL,   -- verifier/hash placeholder
                    meta TEXT,                     -- JSON string
                    version INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,     -- "public" or UUID
                    creator_id TEXT NOT NULL,      -- "system" for public
                    created_at INTEGER,            -- unix ts
                    meta TEXT,                     -- JSON string
                    version INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    role TEXT,                     -- "member" for public
                    wrapped_key TEXT NOT NULL,     -- base64(RSA-OAEP(group_key))
                    added_at INTEGER,
                    PRIMARY KEY (group_id, member_id)
                );
                """
            )
            await db.commit()

    # ---------------- USERS ----------------

    async def upsert_user(
        self,
        user_id: str,
        pubkey_b64url: str,
        privkey_store: str = "",
        pake_password: str = "",
        meta: Optional[Dict[str, Any]] = None,
        version: int = 1,
    ):
        meta_json = json.dumps(meta or {})
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                """
                INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                  pubkey=excluded.pubkey,
                  privkey_store=excluded.privkey_store,
                  pake_password=excluded.pake_password,
                  meta=excluded.meta,
                  version=excluded.version
                """,
                (user_id, pubkey_b64url, privkey_store, pake_password, meta_json, version),
            )
            await db.commit()

    async def get_user_pubkey(self, user_id: str) -> Optional[str]:
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute("SELECT pubkey FROM users WHERE user_id=?", (user_id,))
            row = await cur.fetchone()
            return row[0] if row else None

    async def list_user_ids(self) -> List[str]:
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute("SELECT user_id FROM users")
            rows = await cur.fetchall()
            return [r[0] for r in rows]
        
    async def remove_user(self, user_id: str):
        """
        Remove a user and all their group memberships.
        Does not affect group records themselves.
        """
        async with aiosqlite.connect(self.path) as db:
            # Remove user from any groups first
            await db.execute(
                "DELETE FROM group_members WHERE member_id=?",
                (user_id,),
            )

            # Remove the user record
            await db.execute(
                "DELETE FROM users WHERE user_id=?",
                (user_id,),
            )

            await db.commit()


    # ---------------- GROUPS (PUBLIC) ----------------

    async def ensure_public_group(self, now_ts: int):
        """
        Ensure a 'public' group exists.
        If it exists but in-memory key missing, rotate to start a new epoch.
        """
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute("SELECT group_id FROM groups WHERE group_id='public'")
            row = await cur.fetchone()
            if row:
                if "public" not in self._group_keys:
                    await self.rotate_group_key("public", now_ts)
                return

            await db.execute(
                """
                INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                VALUES ('public', 'system', ?, ?, 1)
                """,
                (now_ts, json.dumps({"title": "Public"})),
            )
            await db.commit()
            self._group_keys["public"] = secrets.token_bytes(32)

    async def rotate_group_key(self, group_id: str, now_ts: int):
        """
        Bump version and set a new in-memory key.
        Rewrap for all current members against their pubkeys.
        """
        new_key = secrets.token_bytes(32)
        self._group_keys[group_id] = new_key

        async with aiosqlite.connect(self.path) as db:
            await db.execute("UPDATE groups SET version = version + 1 WHERE group_id=?", (group_id,))

            cur = await db.execute(
                "SELECT member_id FROM group_members WHERE group_id=?",
                (group_id,),
            )
            members = await cur.fetchall()

            for (member_id,) in members:
                cur2 = await db.execute("SELECT pubkey FROM users WHERE user_id=?", (member_id,))
                row2 = await cur2.fetchone()
                if not row2:
                    continue
                pubkey_b64url = row2[0]
                wrapped = await self._wrap_for_member(pubkey_b64url, new_key)
                await db.execute(
                    "UPDATE group_members SET wrapped_key=? WHERE group_id=? AND member_id=?",
                    (wrapped, group_id, member_id),
                )

            await db.commit()

    async def add_member_to_group(
        self,
        group_id: str,
        member_id: str,
        member_pubkey_b64url: str,
        now_ts: int,
        role: str = "member",
    ):
        """
        Ensure member has a wrapped key for current group epoch.
        If group key not in memory (cold start), rotate to create a new epoch.
        """
        if group_id not in self._group_keys:
            await self.rotate_group_key(group_id, now_ts)

        group_key = self._group_keys[group_id]
        wrapped_key_b64 = await self._wrap_for_member(member_pubkey_b64url, group_key)

        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                """
                INSERT INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(group_id, member_id) DO UPDATE SET
                  role=excluded.role,
                  wrapped_key=excluded.wrapped_key
                """,
                (group_id, member_id, role, wrapped_key_b64, now_ts),
            )
            await db.commit()
            
    async def get_group_version(self, group_id: str) -> int:
        """
        Returns the current version of a group.
        Returns 0 if the group does not exist.
        """
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                "SELECT version FROM groups WHERE group_id=?",
                (group_id,)
            )
            row = await cur.fetchone()
            return row[0] if row else 0

    # ---------------- INTERNAL ----------------

    async def _wrap_for_member(self, pubkey_b64url: str, group_key: bytes) -> str:
        pem = b64url_decode(pubkey_b64url)
        pub = serialization.load_pem_public_key(pem)
        wrapped = pub.encrypt(
            group_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(wrapped).decode("utf-8")


# ====================
# Group 40
# ====================
# Ryan Khor - a1887993
# Lucy Fidock - a1884810
# Nicholas Brown - a1870629
# Luke Schaefer - a1852210
# Nelson Then - a1825642
