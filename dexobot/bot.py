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

    embed = {
        "type": "rich",
        "title": phrase,
        "footer": {"text": "With 💖, DexoBot"},
    }

    return {"embeds": [embed], "flags": 64}


def admin_loader(body):

    user = body["member"]
    permissions = user["permissions"]

    lam = client("lambda")

    # check for management permissions
    print("Checking authorization...")
    authorized = helper.permissions.is_manager(permissions)

    if not authorized:
        print("NOT AUTHORIZED")
        return helper.loader(
            "You are not authorized to run this command", loading_emoji="🛑"
        )
    else:
        print("USER AUTHORIZED :)")

    new_entry = {
        "context": "followup",
        "data": body["data"],
        "member": user,
        "guild_id": body["guild_id"],
        "user_permissions": permissions,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "original_body": body,
    }

    print("invoking lambda...")
    lam.invoke(
        FunctionName=body["invoked-function-arn"],
        InvocationType="Event",
        Payload=json.dumps(new_entry),
    )

    return helper.loader("Loading... DexoBot Friend is here to help!")


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

        return helper.loader("Please wait... Submitting your address to whitelist!")


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

    correct_channel = helper.check_channel(
        guild, body["original_body"]["channel_id"], user_permissions
    )

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

    if not correct_channel:
        title = "😱 Whitelist features are not allowed in this channel."
        description = "Please check with the mods if you are unsure."

    elif not whitelist_open:
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

    if whitelist_open and correct_channel:
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

            if stake_info:
                # only update user count if address was okay
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
        print("Whitelist not open or incorrect channel, not adding anything.")

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

        return helper.loader("Please wait. I'm checking the whitelist for you!")


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

    user_permissions = body["user_permissions"]
    guild_id = body["guild_id"]
    guild = db.collection("servers").document(guild_id)

    correct_channel = helper.check_channel(
        guild, body["original_body"]["channel_id"], user_permissions
    )

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
    if not correct_channel:
        title = "😱 Whitelist features are not allowed in this channel."
        description = "Please check with the mods if you are unsure."

    elif not started:
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


def set_start_time(body):

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

    print("loading DB")
    db = firestore.client()

    print("getting guild ID")
    guild_id = body["guild_id"]
    guild = db.collection("servers").document(guild_id)

    print("Getting params")
    # parse the input parameters
    params = helper.parse_options(body["data"]["options"])
    print("PARAMS:", params)

    begin_time = dt.datetime(
        params["year"]["value"],
        params["month"]["value"],
        params["day"]["value"],
        params["hour"]["value"],
        params["minute"]["value"],
        tzinfo=dt.timezone.utc,
    )

    print(f"Got begin time: {begin_time}")

    guild.collection("config").document("times").update({"begin": begin_time})

    print("Updated begin time!")

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoBot"},
        "title": "⏰ Whitlist starting time set!",
        "fields": [
            {
                "name": "When?",
                "value": f"<t:{int(begin_time.timestamp())}:F>",
                "inline": False,
            },
            {
                "name": "In how long?",
                "value": f"<t:{int(begin_time.timestamp())}:R>",
                "inline": False,
            },
        ],
    }

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


def set_end_time(body):

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

    # parse the input parameters
    params = helper.parse_options(body["data"]["options"])

    end_time = dt.datetime(
        params["year"]["value"],
        params["month"]["value"],
        params["day"]["value"],
        params["hour"]["value"],
        params["minute"]["value"],
        tzinfo=dt.timezone.utc,
    )

    print(f"Got end time: {end_time}")

    guild.collection("config").document("times").update({"end": end_time})

    print("Updated end time!")

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoBot"},
        "title": "🏁 Whitlist closing time set!",
        "fields": [
            {
                "name": "When?",
                "value": f"<t:{int(end_time.timestamp())}:F>",
                "inline": False,
            },
            {
                "name": "In how long?",
                "value": f"<t:{int(end_time.timestamp())}:R>",
                "inline": False,
            },
        ],
    }

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


def close_whitelist_now(body):

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

    if body.get("message"):
        # user clicked a button

        selection = body.get("data").get("custom_id")
        token = helper.get_message_token(guild, body["message"]["interaction"]["id"])

        if selection == "confirm":

            guild.collection("config").document("times").update(
                {"begin": None, "end": firestore.SERVER_TIMESTAMP}
            )

            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoBot"},
                "title": "📪️ Whitlist is now Closed!",
                "fields": [
                    {
                        "name": "Since?",
                        "value": f"<t:{int(dt.datetime.utcnow().timestamp())}:F>",
                        "inline": False,
                    },
                ],
            }

        else:
            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoBot"},
                "title": "😅 Canceled! No changes made",
            }

        # try updating original message:
        success, response = helper.update_discord_message(
            body["message"]["application_id"],
            token,
            {"embeds": [embed], "components": []},
        )

        if success:
            print(f"Deleting token for message {body['message']['interaction']['id']}")
            helper.delete_message_token(guild, body["message"]["interaction"]["id"])
            print(f"Successfully sent update: {response}")
        else:
            print(f"ERROR: Could not update discord messages: {response}")

        return None

    response = {
        "flags": 64,
        "embeds": [
            {
                "type": "rich",
                "title": "Are you absolutely sure?",
                "description": "This will close the whitelist *right now* and overwrite any start or end times you currently have set.",
                "footer": {"text": "With 💖, DexoBot"},
            }
        ],
        "components": [
            {
                "type": 1,
                "components": [
                    {
                        "type": 2,
                        "label": "Cancel",
                        "style": 1,
                        "custom_id": "cancel",
                        "emoji": {"id": None, "name": "🏃"},
                    },
                    {
                        "type": 2,
                        "label": "Confirm",
                        "style": 4,
                        "custom_id": "confirm",
                        "emoji": {"id": None, "name": "🙌"},
                    },
                ],
            }
        ],
    }

    helper.save_message_token(
        guild, body["original_body"]["id"], body["original_body"]["token"]
    )

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        response,
    )

    if success:
        print(f"Successfully sent update: {response}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None


def open_whitelist_now(body):

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

    if body.get("message"):
        # user clicked a button

        selection = body.get("data").get("custom_id")
        token = helper.get_message_token(guild, body["message"]["interaction"]["id"])

        if selection == "confirm":

            guild.collection("config").document("times").update(
                {"begin": firestore.SERVER_TIMESTAMP, "end": None}
            )

            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoBot"},
                "title": "📬️ Whitlist is now open!",
                "fields": [
                    {
                        "name": "Since?",
                        "value": f"<t:{int(dt.datetime.utcnow().timestamp())}:F>",
                        "inline": False,
                    },
                ],
            }

        else:
            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoBot"},
                "title": "😅 Canceled! No changes made",
            }

        # try updating original message:
        success, response = helper.update_discord_message(
            body["message"]["application_id"],
            token,
            {"embeds": [embed], "components": []},
        )

        if success:
            print(f"Deleting token for message {body['message']['interaction']['id']}")
            helper.delete_message_token(guild, body["message"]["interaction"]["id"])
            print(f"Successfully sent update: {response}")
        else:
            print(f"ERROR: Could not update discord messages: {response}")

        return None

    response = {
        "flags": 64,
        "embeds": [
            {
                "type": "rich",
                "title": "Are you absolutely sure?",
                "description": "This will open the whitelist *right now* and overwrite any start or end times you currently have set.",
                "footer": {"text": "With 💖, DexoBot"},
            }
        ],
        "components": [
            {
                "type": 1,
                "components": [
                    {
                        "type": 2,
                        "label": "Cancel",
                        "style": 1,
                        "custom_id": "cancel",
                        "emoji": {"id": None, "name": "🏃"},
                    },
                    {
                        "type": 2,
                        "label": "Confirm",
                        "style": 4,
                        "custom_id": "confirm",
                        "emoji": {"id": None, "name": "🙌"},
                    },
                ],
            }
        ],
    }

    helper.save_message_token(
        guild, body["original_body"]["id"], body["original_body"]["token"]
    )

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        response,
    )

    if success:
        print(f"Successfully sent update: {response}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None


def get_whitelist_info(body):

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

    stats = guild.collection("config").document("stats").get().to_dict()
    times = guild.collection("config").document("times").get().to_dict()
    channel = guild.collection("config").document("channel").get().to_dict()

    start_timestamp = (
        f"<t:{int(times.get('begin').timestamp())}:F>"
        if times.get("begin")
        else "None set"
    )
    end_timestamp = (
        f"<t:{int(times.get('end').timestamp())}:F>" if times.get("end") else "None set"
    )
    active_channel = (
        f"<#{channel.get('active')}>" if channel.get("active") else "None set"
    )

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoBot"},
        "title": "🤓 Whitelist information for your server:",
        "fields": [
            {
                "name": "Total users",
                "value": f"{stats['n_users']}",
                "inline": False,
            },
            # {
            #     "name": "Total user functions executed",
            #     "value": f"{stats['n_calls']}",
            #     "inline": False,
            # },
            {
                "name": "Whitelist Channel",
                "value": active_channel,
                "inline": False,
            },
            {
                "name": "Whitelist opening time",
                "value": start_timestamp,
                "inline": False,
            },
            {
                "name": "Whitelist closing time",
                "value": end_timestamp,
                "inline": False,
            },
        ],
    }

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


def set_channel(body):

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

    params = helper.parse_options(body["data"]["options"])

    current_info = guild.collection("config").document("channel").get().to_dict()
    current_channel = current_info.get("active")

    new_channel = params["channel"]["value"]

    title = ""
    if current_channel:
        if current_channel == new_channel:
            title = f"🤔 Whitelist is already set to this channel."
            description = f"Channel: <#{new_channel}>"

    if not title:
        guild.collection("config").document("channel").set({"active": new_channel})
        title = f"🤝 Successfully set the whitelist channel!"
        description = f"Channel: <#{new_channel}>"

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoBot"},
        "title": title,
        "description": description,
    }

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


def remove_channel(body):

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

    current_info = guild.collection("config").document("channel").get().to_dict()
    current_channel = current_info.get("active")

    if current_channel:
        guild.collection("config").document("channel").set({"active": None})
        title = f"🤝 Whitelist commands are now active in all channels."
    else:
        title = f"🤔 Whitelist was already open in all channels"

    embed = {"type": "rich", "footer": {"text": "With 💖, DexoBot"}, "title": title}

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


def clear_whitelist(body):

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

    if body.get("message"):
        # user clicked a button

        selection = body.get("data").get("custom_id")
        token = helper.get_message_token(guild, body["message"]["interaction"]["id"])

        if selection == "confirm":

            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoBot"},
                "title": "<a:pingpongloading:869290575118082078> Clearing whitelist.",
                "description": "This may take a few minutes. Please be patient and don't run the command again.",
            }

            # try updating original message:
            success, response = helper.update_discord_message(
                body["message"]["application_id"],
                token,
                {"embeds": [embed], "components": []},
            )

            print("Closing WL.")
            guild.collection("config").document("times").update(
                {"begin": None, "end": firestore.SERVER_TIMESTAMP}
            )

            print("Clearing WL")
            # remove all WL entries
            helper.clear_whitelist(guild)

            print("Clearing WL counter.")
            # clear counter
            guild.collection("config").document("stats").update({"n_users": 0})

            embed["title"] = "💨 Whitelist successfully cleared!"
            embed["description"] = "It was time to let go of the past."

        else:
            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoBot"},
                "title": "😅 Canceled!",
                "description": "As if nothing even happened.",
            }

        # try updating original message:
        success, response = helper.update_discord_message(
            body["message"]["application_id"],
            token,
            {"embeds": [embed], "components": []},
        )

        if success:
            print(f"Deleting token for message {body['message']['interaction']['id']}")
            helper.delete_message_token(guild, body["message"]["interaction"]["id"])
            print(f"Successfully sent update: {response}")
        else:
            print(f"ERROR: Could not update discord messages: {response}")

        return None

    response = {
        "flags": 64,
        "embeds": [
            {
                "type": "rich",
                "title": "⚠️ Are you absolutely sure you want to erase the entire whitelist?\nPlease read this entire message very carefully!",
                "description": "1. This will clear the entire whitelist *right now* and you can never go back.\n2. This will close the WL if it is open as a precaution, and erase any programmed start/end times you have set.\n3. If you wish, save a backup of the current state of the whitelist just in case, with the `/export_whitelist` command.",
                "footer": {"text": "With 💖, DexoBot"},
            }
        ],
        "components": [
            {
                "type": 1,
                "components": [
                    {
                        "type": 2,
                        "label": "Cancel",
                        "style": 1,
                        "custom_id": "cancel",
                        "emoji": {"id": None, "name": "🏃"},
                    },
                    {
                        "type": 2,
                        "label": "Confirm",
                        "style": 4,
                        "custom_id": "confirm",
                        "emoji": {"id": None, "name": "🙌"},
                    },
                ],
            }
        ],
    }

    helper.save_message_token(
        guild, body["original_body"]["id"], body["original_body"]["token"]
    )

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        response,
    )

    if success:
        print(f"Successfully sent update: {response}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None


def export_whitelist(body):

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

    wl_dict = helper.whitelist_to_dict(guild)

    wl_json = json.dumps(wl_dict)
    wl_bytes = str.encode(wl_json)

    title = "📂 Attached above is the current state of your whitelist!"
    embed = {"type": "rich", "footer": {"text": "With 💖, DexoBot"}, "title": title}

    now = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M")
    filename = f"./whitelist_{now}_{guild_id}.json"
    files = {"file": (filename, wl_bytes)}

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        {"embeds": [embed]},
    )

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        {"embeds": [embed]},
        files=files,
    )

    if success:
        print(f"Successfully sent update: {embed}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None