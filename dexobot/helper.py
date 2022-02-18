import json
import os

import requests
import binascii

from blockfrost import BlockFrostApi, ApiError
import bech32
import datetime as dt


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


def update_discord_message(application_id, interaction_token, payload, bot_token=None):

    if not bot_token:
        bot_token = os.getenv("DISCORD_BOT_TOKEN")
        assert bot_token

    url = f"https://discord.com/api/v9/webhooks/{application_id}/{interaction_token}/messages/@original"

    print("Sending edit message Payload", payload)
    print("to the URL", url)

    header = {
        "authorization": bot_token,
    }

    res = requests.patch(url, json=payload, headers=header)

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


def post_channel_message(bot_token, channel_id, payload):

    url = f"https://discord.com/api/v9/channels/{channel_id}/messages"

    headers = {
        "authorization": f'Bot {os.getenv("BOT_TOKEN")}',
    }

    print("Sending message Payload", payload)
    print("to the URL", url)
    res = requests.post(url, json=payload, headers=headers)

    if res.ok:
        print(f"Payload sent successfully: {res.json()}")
    else:
        print(f"Error sending payload: {res.json()}")

    return res.json()


def add_role(guild_id, user_id, role_id):

    url = f"https://discord.com/api/v9/guilds/{guild_id}/members/{user_id}/roles/{role_id}"

    headers = {
        "authorization": f'Bot {os.getenv("BOT_TOKEN")}',
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
        "authorization": f'Bot {os.getenv("BOT_TOKEN")}',
    }

    print(f"Adding role {role_id} to user {user_id}")
    res = requests.delete(url, headers=headers)

    if res.ok:
        print(f"Request sent successfully: {res.status_code}.")
    else:
        print(f"Error sending request: {res.status_code}")

    return res.ok


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

    begin_time, end_time = status.get("begin"), status.get("end")
    now = dt.datetime.now(dt.timezone.utc)

    whitelist_open = True
    started = True
    ended = False

    if begin_time:
        if begin_time > now:
            whitelist_open = False
            started = False
        
    if end_time:
        if now > end_time:
            whitelist_open = False
            ended = True

    return whitelist_open, started, ended


def loader(text="Loading...", loading_emoji = None, public = False):

    if not loading_emoji:
        loading_emoji = "⏳️"

    embed = {
        "type": "rich",
        "title": f"{loading_emoji} {text}",
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

    addresses = api.asset_addresses(asset)

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

    if address_type in ["Mainnet Address", "ADA Handle"]:
        print("getting stake")
        got_stake, stake_address = get_stake_address(address)

        if not got_stake:
            return None, None, address_type

    return address, stake_address, address_type