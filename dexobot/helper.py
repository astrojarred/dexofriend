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
def check_minter_status(db, collection):

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            status = db.collection(collection).document("status").get().to_dict()
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    return status.get("online"), status.get("last_online")


def get_time_windows(db, collection):

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            windows = (
                db.collection(collection).document("windows").get().to_dict()["windows"]
            )
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    return windows


def get_current_deadline(deadline_list: list):

    past_dates = []
    future_dates = []

    for date in deadline_list:
        if date > dt.datetime.now(dt.timezone.utc):
            future_dates.append(date)
        else:
            past_dates.append(date)

    past_dates = sorted(past_dates)
    future_dates = sorted(future_dates)

    current_deadline_start = past_dates[-1]
    current_deadline_end = future_dates[0]

    current_window_id = deadline_list.index(current_deadline_start) + 1

    return current_deadline_start, current_deadline_end, current_window_id

def check_window_changing(db, collection):

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            status = db.collection(collection).document("window_change").get().to_dict()
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    return status.get("is_changing")

def check_drop_over(db, collection):

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            status = db.collection(collection).document("minting_over").get().to_dict()
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    return status.get("minting_over")


def date_countdown(deadline):
    left = deadline - dt.datetime.now(dt.timezone.utc)
    return f"{left.days}d {left.seconds // 3600}h {(left.seconds // 60) % 60}m"


def is_final_jeopardy(db, collection: str):

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            info = db.collection(collection).document("final_jeopardy").get().to_dict()
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    return info.get("active"), info.get("timestamp")


# validators
def has_not_minted_yet(
    stake_key, db, tx_out_collection, current_deadline_start, whitelist_id, max_txs_allowed = 5
):

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            transactions_by_stake = [
                item.to_dict()
                for item in db.collection(tx_out_collection)
                .where("stake_address", "==", stake_key)
                .where("type", "==", "success")
                .stream()
            ]
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            transactions_by_user = [
                item.to_dict()
                for item in db.collection(tx_out_collection)
                .where("whitelist_id", "==", whitelist_id)
                .where("type", "==", "success")
                .stream()
            ]
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    successful_transactions = transactions_by_stake + transactions_by_user

    tx_count = 0

    if not successful_transactions:
        return True

    for tx_out in successful_transactions:
        if tx_out["timestamp"] > current_deadline_start:
            tx_count += 1

    if tx_count >= max_txs_allowed:
        return False

    return True


def has_not_minted_in_final_jeopardy(
    db, tx_out_collection, whitelist_id, final_jeopardy_timestamp
):

    try_number = 1
    max_tries = 10
    success = False
    while not success and try_number <= max_tries:
        try:
            # do stuff here
            transactions_by_user = [
                item.to_dict()
                for item in db.collection(tx_out_collection)
                .where("whitelist_id", "==", whitelist_id)
                .where("type", "==", "success")
                .stream()
            ]
            success = True
        except Exception as e:
            print(f"Issue connecting to Firebase: {e}")
            try_number += 1

    successful_transactions = transactions_by_user

    if not successful_transactions:
        return True

    for tx_out in successful_transactions:
        if tx_out["timestamp"] > final_jeopardy_timestamp:
            return False

    return True


def is_eligible_in_current_window(whitelist_info: dict, window_id: int):

    max_window = whitelist_info.get("max_window")

    if max_window:
        if max_window == window_id:
            return True

    return False


def first_whitelisted_before_window(first_whitelisted, current_deadline_start):

    return first_whitelisted < current_deadline_start


def validate_eligibility(db, whitelist_collection, whitelist_info, current_deadline_start, current_window_id, is_final_jeopardy, final_jeopardy_timestamp):

    not_minted_in_final_jeopardy = False
    selected_in_window = False
    not_minted_yet = False
    whitelisted_before_window = False 

    if is_final_jeopardy:
        not_minted_in_final_jeopardy = has_not_minted_in_final_jeopardy(db, f"{whitelist_collection}_tx_out", whitelist_info["user_id"], final_jeopardy_timestamp)
        selected_in_window = is_eligible_in_current_window(whitelist_info, current_window_id)

        if not_minted_in_final_jeopardy and selected_in_window:
            return True, True, True, True

    else:
        not_minted_yet = has_not_minted_yet(whitelist_info.get("stake_address"), db, f"{whitelist_collection}_tx_out", current_deadline_start, whitelist_info["user_id"])
        whitelisted_before_window = first_whitelisted_before_window(whitelist_info.get("first_whitelisted"), current_deadline_start)

        if not_minted_yet and whitelisted_before_window:
            return True, True, True, True


    return not_minted_in_final_jeopardy, selected_in_window, not_minted_yet, whitelisted_before_window

def loading_snail(text="Please wait... Submitting your address to whitelist!", public = False):

    loading_snail = "<a:hoppingsnail:905611122659459092>"

    embed = {
        "type": "rich",
        "title": f"{loading_snail} {text}",
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