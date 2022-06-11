import json
import os
import time

import requests
import binascii

from blockfrost import BlockFrostApi, ApiError
import bech32
import datetime as dt

from dexobot import roles


# slash command helper functions
def parse_options(options):
    """Take a list of option dicts and return a single dictionary"""

    option_types = {
        1: "SUB_COMMAND",
        2: "SUB_COMMAND_GROUP",
        3: "STRING",
        4: "INTEGER",
        5: "BOOLEAN",
        6: "USER",
        7: "CHANNEL",
        8: "ROLE",
        9: "MENTIONABLE",
        10: "NUMBER",
    }

    ops_parsed = {}

    for op in options:
        name = op["name"]
        ops_parsed[name] = {}
        ops_parsed[name]["type"] = option_types[int(op["type"])]
        ops_parsed[name]["value"] = op["value"]

    return ops_parsed


def is_bot_channel(channel_id):

    if channel_id in json.loads(os.environ.get("BOT_CHANNELS")):
        return True
    else:
        return False


# discord webhook helper functions
def send_discord_payload(bot_token, interaction_id, interaction_token, payload):

    url = f"https://discord.com/api/v9/interactions/{interaction_id}/{interaction_token}/callback"

    typed_payload = {"type": 4, "data": payload}

    print("Sending Payload", typed_payload)
    res = requests.post(url, typed_payload)

    if res.ok:
        print(f"Payload sent successfully: {res.json()}")
    else:
        print(f"Error sending payload: {res.json()}")

    return res.ok


def send_discord_followup(bot_token, application_id, interaction_token, payload):

    url = f"https://discord.com/api/v9/webhooks/{application_id}/{interaction_token}"

    print("Sending followup Payload", payload)
    print("to the URL", url)
    res = requests.post(url, json=payload)

    if res.ok:
        print(f"Payload sent successfully: {res.json()}")
    else:
        print(f"Error sending payload: {res.json()}")

    return res.ok


def update_discord_message(
    application_id, interaction_token, payload, files=None, bot_token=None
):

    if not bot_token:
        bot_token = os.getenv("DISCORD_BOT_TOKEN")
        assert bot_token

    url = f"https://discord.com/api/v9/webhooks/{application_id}/{interaction_token}/messages/@original"

    print("Sending edit message Payload", payload)
    print("to the URL", url)

    header = {
        "authorization": bot_token,
    }

    res = requests.patch(url, json=payload, headers=header, files=files)

    if res.ok:
        print(f"Payload sent successfully: {res.json()}")
    else:
        print(f"Error sending payload: {res.json()}")

    return res.ok, res.json()


def create_followup_message(application_id, interaction_token, payload, bot_token=None):

    if not bot_token:
        bot_token = os.getenv("DISCORD_BOT_TOKEN")
        assert bot_token

    url = f"https://discord.com/api/v9/webhooks/{application_id}/{interaction_token}"

    print("Sending followup message Payload", payload)
    print("to the URL", url)

    header = {
        "authorization": bot_token,
    }

    res = requests.post(url, data=payload, headers=header)

    if res.ok:
        print(f"Payload sent successfully: {res.json()}")
    else:
        print(f"Error sending payload: {res.json()}")

    return res.ok, res.json()


def delete_original_message(application_id, interaction_token, bot_token=None):

    if not bot_token:
        bot_token = os.getenv("DISCORD_BOT_TOKEN")
        assert bot_token

    url = f"https://discord.com/api/v9/webhooks/{application_id}/{interaction_token}/messages/@original"

    print("Deleting original message")
    print("to the URL", url)

    header = {
        "authorization": bot_token,
    }

    res = requests.delete(url, headers=header)

    if res.ok:
        print(f"Interaction Response deleted successfully: {res.json()}")
    else:
        print(f"Error sending payload: {res.json()}")

    return res.ok, res.json()


def post_channel_message(channel_id, payload, bot_token=None):

    url = f"https://discord.com/api/v9/channels/{channel_id}/messages"

    headers = {
        "authorization": f'Bot {os.getenv("BOT_TOKEN") if not bot_token else bot_token}',
    }

    print("Sending message Payload", payload)
    print("to the URL", url)
    res = requests.post(url, json=payload, headers=headers)

    if res.ok:
        print(f"Payload sent successfully: {res.json()}")
    else:
        print(f"Error sending payload: {res.json()}")

    return res.json()


def add_role(guild_id, user_id, role_id, bot_token=None):

    url = f"https://discord.com/api/v9/guilds/{guild_id}/members/{user_id}/roles/{role_id}"

    headers = {
        "authorization": f'Bot {os.getenv("BOT_TOKEN") if not bot_token else bot_token}',
    }

    print(f"Adding role {role_id} to user {user_id}")
    res = requests.put(url, headers=headers)

    if res.ok:
        print(f"Request sent successfully: {res.status_code}.")
    else:
        print(f"Error sending request: {res.status_code}")

    return res.ok


def remove_role(guild_id, user_id, role_id):

    url = f"https://discord.com/api/v9/guilds/{guild_id}/members/{user_id}/roles/{role_id}"

    headers = {
        "authorization": f'Bot {os.getenv("DISCORD_BOT_TOKEN")}',
    }

    print(f"Adding role {role_id} to user {user_id}")
    res = requests.delete(url, headers=headers)

    if res.ok:
        print(f"Request sent successfully: {res.status_code}.")
    else:
        print(f"Error sending request: {res.status_code}")

    return res.ok


def get_guild_info(guild_id, bot_token=None):

    url = f"https://discord.com/api/v9/guilds/{guild_id}"

    headers = {
        "authorization": f'Bot {os.getenv("DISCORD_BOT_TOKEN") if not bot_token else bot_token}',
    }
    print(f"Getting guild info for guild {guild_id}")
    res = requests.get(url, headers=headers)

    if res.ok:
        print(f"Request sent successfully: {res.status_code}.")
    else:
        print(f"Error sending request: {res.status_code}")

    return res.json()



def create_channel_invite(channel_id, bot_token=None):

    url = f"https://discord.com/api/v9/channels/{channel_id}/invites"

    headers = {
        "authorization": f'Bot {os.getenv("DISCORD_BOT_TOKEN") if not bot_token else bot_token}',
    }

    print(f"Adding guild info for channel {channel_id}")
    res = requests.post(url, headers=headers, json={"max_age": 0})

    if res.ok:
        print(f"Request sent successfully: {res.status_code}.")
    else:
        print(f"Error sending request: {res.status_code}")

    return res.json()


def post_channel_message(message_payload, channel_id, bot_token=None):

    url = f"https://discord.com/api/v9/channels/{channel_id}/messages"

    headers = {
        "authorization": f'Bot {os.getenv("DISCORD_BOT_TOKEN") if not bot_token else bot_token}',
    }

    print(f"Adding guild info for channel {channel_id}")
    res = requests.post(url, headers=headers, json=message_payload)

    if res.ok:
        print(f"Request sent successfully: {res.status_code}.")
    else:
        print(f"Error sending request: {res.status_code}")

    return res.json()


def edit_channel_message(
    channel_id, message_id, payload, files=None, bot_token=None
):

    if not bot_token:
        bot_token = os.getenv("DISCORD_BOT_TOKEN")
        assert bot_token

    url = f"https://discord.com/api/v9/channels/{channel_id}/messages/{message_id}"

    print("Sending edit message Payload", payload)
    print("to the URL", url)

    header = {
         "authorization": f'Bot {os.getenv("BOT_TOKEN") if not bot_token else bot_token}',
    }

    res = requests.patch(url, json=payload, headers=header, files=files)

    if res.ok:
        print(f"Payload sent successfully: {res.json()}")
    else:
        print(f"Error sending payload: {res.json()}")

    return res.ok, res.json()



def get_stake_address(address):
    """Calculate stake address given a cardano payment address"""

    try:

        decoded_address = bech32.bech32_decode(address)

        hex_address = bech32.convertbits(decoded_address[1], 5, 16)

        account = "".join([f"{h:04x}" for h in hex_address])[-58:-2]
        account = "e1" + account

        bytes_account = bytes.fromhex(account)

        decoded_stake_address = bech32.convertbits(bytes_account, 8, 5)

        stake_address = bech32.bech32_encode("stake", decoded_stake_address)

        return True, stake_address

    except Exception as e:

        return False, None


# database stuff
def check_whitelist_open(guild):

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            status = guild.collection("config").document("times").get().to_dict()
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    if status:
        begin_time, end_time = status.get("begin"), status.get("end")
    else:
        begin_time, end_time = None, None
        
    now = dt.datetime.now(dt.timezone.utc)

    whitelist_open = False
    started = False
    ended = False

    if begin_time:
        if begin_time < now:
            started = True

    if end_time:
        if now > end_time:
            ended = True

    print(started, ended)
    if (started, ended) in [(True, False), (True, None), (None, False)]:
        whitelist_open = True

    return whitelist_open, started, ended


def loader(text="Loading...", loading_emoji=None, public=False):

    if not loading_emoji:
        loading_emoji = "⏳️"
        # loading_emoji = "<a:pingpongloading:869290575118082078>"

    embed = {
        "type": "rich",
        "title": f"{loading_emoji} {text}",
        "color": 0xFF5ACD if "not authorized" not in text else 0xC8414C,
        "description": "Taking more than 30s? Dismiss this message and try again.",
    }

    if public:
        return {"embeds": [embed]}
    else:
        return {"embeds": [embed], "flags": 64}


def load_api(BLOCKFROST_ID=None):

    if not BLOCKFROST_ID:
        BLOCKFROST_ID = os.getenv("BLOCKFROST_ID")

    return BlockFrostApi(BLOCKFROST_ID)


def resolve_ada_handle(handle):

    api = load_api()

    if handle[0] == "$":
        handle = handle[1:]

    policy = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"

    asset = policy + binascii.hexlify(str.encode(handle)).decode("utf-8")

    try:
        addresses = api.asset_addresses(asset)
    except ApiError:
        print(f"Ada handle {handle} does not exist.")
        return None

    try:
        return addresses[0].address
    except KeyError:
        return None


def parse_address(address):

    handle = None
    stake_address = None

    if address[:4] == "addr":
        address_type = "Mainnet Address"
    elif address[0] == "$":
        handle = str(address)
        address_type = "ADA Handle"
    elif address[:5] == "stake":
        address_type = "Stake Address"
        stake_address = address
        address = ""
    else:
        return None, None, None

    print(f"Found address type {address_type}")

    if handle:
        address = resolve_ada_handle(handle)
        print("handle_address", address)

        if not address:  # ada handle does not exist
            return None, None, address_type

    if address_type in ["Mainnet Address", "ADA Handle"]:
        print("getting stake")
        got_stake, stake_address = get_stake_address(address)

        if not got_stake:
            return None, None, address_type

    return address, stake_address, address_type


class permissions:

    CREATE_INSTANT_INVITE = 0x0000000000000001
    KICK_MEMBERS = 0x0000000000000002
    BAN_MEMBERS = 0x0000000000000004
    ADMINISTRATOR = 0x0000000000000008
    MANAGE_CHANNELS = 0x0000000000000010
    MANAGE_GUILD = 0x0000000000000020
    ADD_REACTIONS = 0x0000000000000040
    VIEW_AUDIT_LOG = 0x0000000000000080
    PRIORITY_SPEAKER = 0x0000000000000100
    STREAM = 0x0000000000000200
    VIEW_CHANNEL = 0x0000000000000400
    SEND_MESSAGES = 0x0000000000000800
    SEND_TTS_MESSAGES = 0x0000000000001000
    MANAGE_MESSAGES = 0x0000000000002000
    EMBED_LINKS = 0x0000000000004000
    ATTACH_FILES = 0x0000000000008000
    READ_MESSAGE_HISTORY = 0x0000000000010000
    MENTION_EVERYONE = 0x0000000000020000
    USE_EXTERNAL_EMOJIS = 0x0000000000040000
    VIEW_GUILD_INSIGHTS = 0x0000000000080000
    CONNECT = 0x0000000000100000
    SPEAK = 0x0000000000200000
    MUTE_MEMBERS = 0x0000000000400000
    DEAFEN_MEMBERS = 0x0000000000800000
    MOVE_MEMBERS = 0x0000000001000000
    USE_VAD = 0x0000000002000000
    CHANGE_NICKNAME = 0x0000000004000000
    MANAGE_NICKNAMES = 0x0000000008000000
    MANAGE_ROLES = 0x0000000010000000
    MANAGE_WEBHOOKS = 0x0000000020000000
    MANAGE_EMOJIS_AND_STICKERS = 0x0000000040000000
    USE_APPLICATION_COMMANDS = 0x0000000080000000
    REQUEST_TO_SPEAK = 0x0000000100000000
    MANAGE_EVENTS = 0x0000000200000000
    MANAGE_THREADS = 0x0000000400000000
    CREATE_PUBLIC_THREADS = 0x0000000800000000
    CREATE_PRIVATE_THREADS = 0x0000001000000000
    USE_EXTERNAL_STICKERS = 0x0000002000000000
    SEND_MESSAGES_IN_THREADS = 0x0000004000000000
    START_EMBEDDED_ACTIVITIES = 0x0000008000000000
    MODERATE_MEMBERS = 0x0000010000000000

    @staticmethod
    def has(user_permissions, permission_to_check):

        return (int(user_permissions) & permission_to_check) == permission_to_check

    @staticmethod
    def is_admin(user_permissions, permission_to_check=ADMINISTRATOR):

        return (int(user_permissions) & permission_to_check) == permission_to_check

    @staticmethod
    def is_manager(user_permissions, permission_to_check=MANAGE_ROLES):

        return (int(user_permissions) & permission_to_check) == permission_to_check


def update_guild_info(db, guild_id, bot_token=None):

    guild_info = get_guild_info(guild_id, bot_token=bot_token)

    db.collection("servers").document(guild_id).set(guild_info, merge=True)


def check_channel(guild_db, current_channel, user_permissions):

    current_info = guild_db.collection("config").document("channel").get().to_dict()

    if current_info:
        active_channel = current_info.get("active")
    else:
        active_channel = None

    # check if manager
    manager = permissions.is_manager(user_permissions)

    if manager:
        # managers can do it from anywhere
        return True
    elif not active_channel:
        return True

    elif current_channel != active_channel:
        return False
    else:
        return True


def save_message_token(guild_db, message_id, token):

    guild_db.collection("tokens").document(message_id).set({"token": token})


def get_message_token(guild_db, message_id):

    message_info = guild_db.collection("tokens").document(message_id).get().to_dict()

    token = message_info.get("token")

    return token


def delete_message_token(guild_db, message_id):

    guild_db.collection("tokens").document(message_id).delete()


def clear_whitelist(guild_db, batch_size=50):

    docs = guild_db.collection("whitelist").limit(batch_size).stream()

    n_deleted = 0

    for doc in docs:
        doc.reference.delete()
        n_deleted += 1

    print(f"Deleted {n_deleted} docs")

    time.sleep(0.1)

    if n_deleted >= batch_size:
        clear_whitelist(guild_db, batch_size)


def whitelist_to_dict(guild_db):

    docs = guild_db.collection("whitelist").stream()

    whitelist = {}

    for doc in docs:

        user = doc.to_dict()

        user_id = user["user_id"]
        user["first_whitelisted_unix_utc"] = int(user["first_whitelisted"].timestamp())

        try:
            user["last_updated_unix_utc"] = int(user["timestamp"].timestamp())
        except AttributeError:
            user["last_updated_unix_utc"] = int(user["first_whitelisted"].timestamp())

        del user["first_whitelisted"]
        del user["timestamp"]

        whitelist[user_id] = user

    return whitelist


def keep_warm():

    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore

    print("Connecting to firestore.")
    # Use the application default credentials
    if not firebase_admin._apps:
        cert = json.loads(os.getenv("FIREBASE_CERT"))
        cred = credentials.Certificate(cert)
        firebase_app = firebase_admin.initialize_app(cred)

    db = firestore.client()



def gather_stake_assets(stake_addresses):

    api = load_api()

    if not isinstance(stake_addresses, list):
        stake_addresses = [stake_addresses]

    l = {}

    for stake in stake_addresses:

        assets = api.account_addresses_assets(stake, gather_pages=True)

        for a in assets:
            pid = a.unit[:56]
            aname = binascii.unhexlify(a.unit[56:]).decode("utf-8")
            q = int(a.quantity)

            if not l.get(pid):
                l[pid] = {}

            l[pid][aname] = q

    return l

def modify_user_role(guild_id, user_id, role_id, method="add",  bot_token=None):

    if not bot_token:
        bot_token = os.getenv("DISCORD_BOT_TOKEN")
        assert bot_token

    url = f"https://discord.com/api/v9/guilds/{guild_id}/members/{user_id}/roles/{role_id}"

    header = {
        "authorization": f"Bot {bot_token}",
    }

    if method != "add":
        verb = "removed from"
        res = requests.delete(url, headers=header)
    else:
        verb = "added to"
        res = requests.put(url, headers=header)

    if res.ok:
        print(f"Role {verb} user: {res.text}")
        return True
    else:
        print(f"Error, role not {verb} user: {res.text}")
        return False


def sync_user_assets(user_doc, wallets=None):

    user_info = user_doc.get().to_dict()

    if not wallets:
        # connect to firebase
        import firebase_admin
        from firebase_admin import credentials
        from firebase_admin import firestore

        print("Connecting to firestore.")
        # Use the application default credentials
        if not firebase_admin._apps:
            cert = json.loads(os.getenv("DEXO_FIREBASE_CERT"))
            cred = credentials.Certificate(cert)
            firebase_app = firebase_admin.initialize_app(cred)

        db = firestore.client()

        wallets = user_info.get("stake_addresses")

    if not wallets:
        return wallets, {} # wallets updates, polices found

    # get user's assets
    assets = gather_stake_assets(wallets)

    # update assets dict
    user_doc.set({"user_assets": assets}, merge=True)

    return wallets, assets


def update_user_roles(guild_docs, user_doc, wallets=None, resync=False):

    if not isinstance(guild_docs, list):
        guild_docs = [guild_docs]

    for doc in guild_docs:

        guild_id = doc.id
        user_id = user_doc.id

        holder_roles = doc.collection("config").document("roles").get().to_dict()

        current_roles = get_guild_member(guild_id, user_id, roles_only=True)

        if resync:
            wallet_updates, user_assets = sync_user_assets(user_doc, wallets)
        else:
            user_assets = user_doc.get().to_dict().get("user_assets")

        user_policies = list(user_assets.keys())

        roles_added = []
        roles_removed = []
        user_holder_roles = []

        for role_id, policy in holder_roles.items():

            # if it's a special role assignment, starting with !!
            if policy in list(roles.SPECIAL_CODES.keys()):
                policy_function = roles.SPECIAL_CODES[policy]["function"]
                concerned_policies = roles.SPECIAL_CODES[policy]["policies"]

                # if they hold a relevant policy OR they already have the role
                if any(item in user_policies for item in concerned_policies) or (role_id in current_roles):

                    # check if the should have the role
                    needs_role = policy_function(user_assets)

                    if role_id not in current_roles and needs_role:
                        modify_user_role(guild_id, user_id, role_id, "add")
                        roles_added.append(role_id)
                        user_holder_roles.append(role_id)
                    elif role_id in current_roles and not needs_role:
                        modify_user_role(guild_id, user_id, role_id, "remove")
                        roles_removed.append(role_id)
                    elif role_id in current_roles:
                        user_holder_roles.append(role_id)

            # a normal policy ID
            else:
                if role_id not in current_roles and policy in user_policies:
                    modify_user_role(guild_id, user_id, role_id, "add")
                    roles_added.append(role_id)
                    user_holder_roles.append(role_id)
                elif role_id in current_roles and policy not in user_policies:
                    modify_user_role(guild_id, user_id, role_id, "remove")
                    roles_removed.append(role_id)
                elif role_id in current_roles:
                    user_holder_roles.append(role_id)

    return roles_added, roles_removed, user_holder_roles


def get_guild_member(guild_id, user_id, roles_only=False, bot_token=None):

    if not bot_token:
        bot_token = os.getenv("DISCORD_BOT_TOKEN")
        assert bot_token

    url = f"https://discord.com/api/v9/guilds/{guild_id}/members/{user_id}"

    header = {
        "authorization": f"Bot {bot_token}",
    }

    res = requests.get(url, headers=header)

    if not res.ok:
        print(f"Error reaching get guild member: {res.json()}")
        return False, {}

    if roles_only:
        return True, res.json()["roles"]

    return True, res.json()


