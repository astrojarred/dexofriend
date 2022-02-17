from dexobot import helper

from os import getenv
import datetime as dt
import json

from boto3 import resource, client

# from botocore.exceptions import ClientError
from blockfrost import BlockFrostApi, ApiError, ApiUrls
import binascii
import urllib.parse


def constant(body):

    which_constant = body["data"]["options"][0]["value"]

    if which_constant == "gravity":
        phrase = "🏋️ The gravitational constant (G) is `6.674 × 10^−11 m3/(kg s2)`. That's actually pretty weak!"
    elif which_constant == "light":
        phrase = "⚡️ The speed of light (c) is `2.9979 × 10^8 m/s`. Wow!"
    elif which_constant == "parsec":
        phrase = "🚀 One parsec (pc) is equal to `3.086 × 10^16 m` or `3.262 light-years`. That's a unit of length, dude!"
    elif which_constant == "planck":
        phrase = "🔬 Planck's Constant (*h*) is 6`.62607 × 10^−34 J/Hz`. No ultraviolet catastrophes here!"

    return phrase


def whitelist(body):

    # parse the input parameters
    params = helper.parse_options(body["data"]["options"])

    user = body["member"]
    guild_id = body["guild_id"]

    # the address they submitted
    address = params["address"]["value"]

    # get valid roles - ADD LATER
    # whitelist_role_string = getenv("WHITELIST_ROLES")
    # assert whitelist_role_string
    # whitelist_role_ids = json.loads(whitelist_role_string)

    user_roles = user["roles"]

    # posted_channel = body.get("channel_id")
    # whitelist_channels = ["907009511204728983"]

    # check for errors:
    error_message = None

    # if not posted_channel in whitelist_channels:
    #     error_message = f"Please try again in the bot channel: "
    #     for channel_id in whitelist_channels:
    #         error_message += f"<#{channel_id}> "
    fields = []

    # if not any(x in whitelist_role_ids for x in user_roles):
    #    error_title = "<:sadfrog:898565061239521291> You don't have permission to whitelist."
    #    error_message = "Sorry, the whitelist function is for certain roles only. Please see <#900299272996671518> for more information.\nThank you for your enthusiasm, and stay tuned!"
    if address[:4] == "addr" and len(address) < 58:
        error_title = (
            "<:sadfrog:898565061239521291> There was an error processing your address."
        )
        error_message = f"Address too short!"
        fields.append(
            {
                "name": "Address",
                "value": f"`{address}`",
                "inline": False,
            },
        )

    if error_message:
        embed = {
            "type": "rich",
            "title": error_title,
            "description": error_message,
            "footer": {"text": "With 💖, DexoBot"},
        }

        embed["fields"] = fields

        print(f"ERROR: {error_message}")
        return {"embeds": [embed], "flags": 64}

    else:
        # return add addy to whitelist

        lam = client("lambda")

        new_entry = {
            "context": "followup",
            "data": {"name": "add_whitelist_entry"},
            "original_body": body,
            "guild_id": guild_id,
            "user_permissions": user["permissions"],
            "whitelist_info": {
                "address": address,
                "user_id": user["user"]["id"],
                "discriminator": user["user"]["discriminator"],
                "username": user["user"]["username"],
                "roles": user_roles,
                "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                "method": "dexobot",
            },
        }

        lam.invoke(
            FunctionName=body["invoked-function-arn"],
            InvocationType="Event",
            Payload=json.dumps(new_entry),
        )

        return helper.loader()


def add_whitelist_entry(body):

    # add addy to whitelist
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore

    print("Connecting to firestore.")
    # Use the application default credentials
    if not firebase_admin._apps:
        cert = json.loads(getenv("FIREBASE_CERT"))
        cred = credentials.Certificate(cert)
        firebase_app = firebase_admin.initialize_app(cred)

    db = firestore.client()

    info = body["whitelist_info"]
    guild_id = body["guild_id"]
    user_permissions = body["user_permissions"]

    guild = db.collection("servers").document(guild_id)
    whitelist_open, started, ended = helper.check_whitelist_open(guild)
    print(f"Is open: {whitelist_open}, Started: {started}, Ended: {ended}")

    # add timestamp
    info["timestamp"] = firestore.SERVER_TIMESTAMP  # dt.datetime.now(dt.timezone.utc)

    # check the cardano address
    provided_address = info["address"]
    address, stake_info, type_provided = helper.parse_address(provided_address)
    # got_stake, stake_info = helper.get_stake_address(info["address"])

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoBot"},
    }

    fields = []

    if not whitelist_open:
        if not started:
            title = "⏰ This whitelist is not open yet."
            description = "Please check back later."
        else:  # ended
            title = "⏰ This whitelist is currently closed."
            description = "Thanks for participating!"


    elif stake_info:
        info["stake_address"] = stake_info
        info["ok"] = True
        info["error"] = None

        poolpm = f"https://pool.pm/{stake_info}"

        title = "✨ Successfully submitted to the whitelist!"
        description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[{info['stake_address']}]({poolpm})**"

        fields.append(
            {
                "name": f"{type_provided} provided:",
                "value": provided_address,
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "Note",
                "value": "You can check your status at any time with the `/check_whitelist` command.",
                "inline": False,
            },
        )

    else:
        info["stake_address"] = None
        info["ok"] = False
        info["error"] = f"Error calculating stake address: f{stake_info}."

        title = "😢 There was an error processing your address!"
        description = f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket."

        fields.append(
            {
                "name": "Provided Address",
                "value": provided_address,
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "Error",
                "value": f"Error calculating stake address: `{stake_info}`.",
                "inline": False,
            },
        )

    embed["title"] = title
    embed["description"] = description
    embed["fields"] = fields

    if whitelist_open:
        print(f"Adding to the whitelist: {info}")

        # get current info on the whitelist
        current_info = guild.collection("whitelist").document(info["user_id"]).get()

        if current_info.exists:
            # update the already-existign entry
            guild.collection("whitelist").document(str(info["user_id"])).update(info)

            guild.collection("config").document("stats").update(
                {"n_calls": firestore.Increment(1)}
            )

        else:
            # if it's a first addition, add the whitelist date seperately
            info["first_whitelisted"] = info["timestamp"]
            guild.collection("whitelist").document(str(info["user_id"])).set(info)

            # update the stats dictionary
            guild.collection("config").document("stats").update(
                {"n_users": firestore.Increment(1)}
            )
            guild.collection("config").document("stats").update(
                {"n_calls": firestore.Increment(1)}
            )
            # guild.collection("config").document("users").update(
            #     {"ids": firestore.ArrayUnion([info["user_id"]])}
            # )
    else:
        print("Whitelist not open, not adding anything.")

    print("Sending discord_update")
    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        {"embeds": [embed]},
    )

    if success:
        print("Successfully added!")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None


def check_whitelist(body):

    user = body["member"]
    user_id = user["user"]["id"]
    guild_id = body["guild_id"]
    user_roles = user["roles"]
    user_permissions = user["permissions"]

    # get valid roles
    # whitelist_role_string = getenv("WHITELIST_ROLES")
    # assert whitelist_role_string
    # whitelist_role_ids = json.loads(whitelist_role_string)

    # posted_channel = body.get("channel_id")
    # whitelist_channels = ["907009511204728983"]

    # check for errors:
    error_message = None
    error_title = ""

    # if not posted_channel in whitelist_channels:
    #     error_message = f"Please try again in the bot channel: "
    #     for channel_id in whitelist_channels:
    #         error_message += f"<#{channel_id}> "
    # if not any(x in whitelist_role_ids for x in user_roles):
    #     error_title = "<:sadfrog:898565061239521291> You don't have permission to whitelist."
    #     error_message = "Sorry, the whitelist function is for certain roles only. Please see <#900299272996671518> for more information.\nThank you for your enthusiasm, and stay tuned!"

    if error_message:
        embed = {
            "type": "rich",
            "title": error_title,
            "description": error_message,
            "footer": {"text": "With 💖, DexoBot"},
        }

        print(f"ERROR: {error_title} -- {error_message}")
        return {"embeds": [embed], "flags": 64}

    else:

        lam = client("lambda")

        new_entry = {
            "context": "followup",
            "data": {"name": "check_whitelist_followup"},
            "original_body": body,
            "guild_id": guild_id,
            "user_permissions": user["permissions"],
            "whitelist_info": {
                "user_id": user["user"]["id"],
                "discriminator": user["user"]["discriminator"],
                "username": user["user"]["username"],
                "roles": user_roles,
                "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                "method": "dexobot",
            },
        }

        lam.invoke(
            FunctionName=body["invoked-function-arn"],
            InvocationType="Event",
            Payload=json.dumps(new_entry),
        )

        return helper.loading_snail("Please wait... Checking the whitelist for you!")


def check_whitelist_followup(body):

    # check the whitelist
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore

    print("Connecting to firestore.")
    # Use the application default credentials
    if not firebase_admin._apps:
        cert = json.loads(getenv("FIREBASE_CERT"))
        cred = credentials.Certificate(cert)
        firebase_app = firebase_admin.initialize_app(cred)

    db = firestore.client()

    guild_id = body["guild_id"]
    guild = db.collection("servers").document(guild_id)

    whitelist_info = body["whitelist_info"]

    info = (
        guild.collection("whitelist")
        .document(whitelist_info["user_id"])
        .get()
        .to_dict()
    )
    print("User info:", info)

    # check if WL is open
    whitelist_open, started, ended = helper.check_whitelist_open(guild)

    print(f"Is open: {whitelist_open}, Started: {started}, Ended: {ended}")

    fields = []
    embed = {
        "type": "rich",
        # "author": {"name": "Happy Hoppers Main Drop"},
        "footer": {"text": "With 💖, DexoBot"},
    }

    # if WL not open yet
    if not started:
        title = "⏰ Whitelist is not open yet."
        description = "Please check back later."

    # if WL open
    else:

        if info:
            if not info["error"]:

                poolpm = f"https://pool.pm/{info['stake_address']}"
                title = "✨ Found whitelisted address!"
                description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[{info['stake_address']}]({poolpm})**\n\nClick the pool.pm link above and make sure it shows the Cardano wallet you intend to send ADA from to mint."

            else:

                title = "😢 There was an error processing the address"
                description = f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket."

                fields.append(
                    {
                        "name": "Error",
                        "value": f"`{info['error']}`",
                        "inline": False,
                    },
                )

                fields.append(
                    {
                        "name": "Stake Address",
                        "value": f"`{info['stake_address']}`",
                        "inline": False,
                    },
                )

        else:
            title = "🤔 Unable to find this user on the whitelist."

            if not ended:
                description = "Try adding youself with the `/whitelist` command."
            else:
                description = "The whitelist is currently closed."

    embed["title"] = title
    embed["description"] = description
    embed["fields"] = fields

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        {"embeds": [embed]},
    )

    if success:
        print(f"Successfully sent update: {embed}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None
