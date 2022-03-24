from re import M
from dexobot import helper

from os import getenv
import datetime as dt
import json

from boto3 import resource, client

# from botocore.exceptions import ClientError
from blockfrost import BlockFrostApi, ApiError, ApiUrls
import binascii
import urllib.parse


class Colors:

    SUCCESS = 0x09A67B
    FAIL = 0xC8414C
    INFO = 0xFF5ACD
    STATUSQUO = 0x60D4FB


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
        "footer": {"text": "With 💖, DexoFriend"},
        "color": Colors.STATUSQUO,
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

    return helper.loader("Loading... DexoFriend is here to help!")


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
        error_title = "😢 There was an error processing your address."
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
            "footer": {"text": "With 💖, DexoFriend"},
            "color": Colors.FAIL,
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
        "footer": {"text": "With 💖, DexoFriend"},
        "color": Colors.FAIL,
    }

    fields = []

    # get current info on the whitelist
    current_info = guild.collection("whitelist").document(info["user_id"]).get()

    if not correct_channel:
        title = "😱 Whitelist features are not allowed in this channel."
        description = "Please check with the mods if you are unsure."

    elif not current_info.exists:
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

        title = f"✨ Congrats! Your address has been {'updated on' if current_info.exists else 'added to'} the whitelist!"
        description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[<a:arrow_right:949342031166193714>{info['stake_address']}]({poolpm})**"

        fields.append(
            {
                "name": f"📋️ {type_provided} provided:",
                "value": f"`{provided_address}`",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "👀 Note",
                "value": "You can confirm your status at any time with the `/check_whitelist` command.",
                "inline": False,
            },
        )

        embed["color"] = Colors.SUCCESS

    else:
        info["stake_address"] = None
        info["ok"] = False
        info["error"] = f"Error calculating stake address: f{stake_info}."

        title = "😢 There was an error processing your address!"
        description = f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket."

        fields.append(
            {
                "name": "📋️ Provided Address",
                "value": f"`{provided_address}`",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "❗️ Error",
                "value": f"Error calculating stake address: `{stake_info}`.",
                "inline": False,
            },
        )

    embed["title"] = title
    embed["description"] = description
    embed["fields"] = fields

    if (whitelist_open or current_info.exists) and correct_channel:
        print(f"Adding to the whitelist: {info}")

        # current_info = guild.collection("whitelist").document(info["user_id"]).get()

        if current_info.exists:
            # update the already-existign entry
            guild.collection("whitelist").document(str(info["user_id"])).set(
                info, merge=True
            )

            guild.collection("config").document("stats").set(
                {"n_calls": firestore.Increment(1)}, merge=True
            )

        else:
            # if it's a first addition, add the whitelist date seperately
            info["first_whitelisted"] = info["timestamp"]
            guild.collection("whitelist").document(str(info["user_id"])).set(info)

            # update the stats dictionary

            if stake_info:
                # only update user count if address was okay
                guild.collection("config").document("stats").set(
                    {"n_users": firestore.Increment(1)}, merge=True
                )

            guild.collection("config").document("stats").set(
                {"n_calls": firestore.Increment(1)}, merge=True
            )

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


def manually_add_user(body):

    # manually dd addy for user to whitelist
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

    print("Getting params")
    # parse the input parameters
    params = helper.parse_options(body["data"]["options"])
    print("PARAMS:", params)

    guild_id = body["guild_id"]
    provided_address = params.get("address")["value"]
    user_id = params.get("user")["value"]
    days_ago = params.get("days_ago")
    user_info = body["data"]["resolved"]["users"][user_id]
    user_roles = body["data"]["resolved"]["members"][user_id]["roles"]

    guild = db.collection("servers").document(guild_id)

    # check the cardano address
    address, stake_info, type_provided = helper.parse_address(provided_address)

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "color": Colors.FAIL,
    }

    fields = []

    info = {
        "address": provided_address,
        "user_id": user_id,
        "discriminator": user_info["discriminator"],
        "username": user_info["username"],
        "roles": user_roles,
        "method": "manual",
        "timestamp": firestore.SERVER_TIMESTAMP,
    }

    first_whitelisted = None
    if days_ago:
        now = dt.datetime.now(dt.timezone.utc)
        first_whitelisted = now - dt.timedelta(days=int(days_ago["value"]))

    if stake_info:
        info["stake_address"] = stake_info
        info["ok"] = True
        info["error"] = None

        poolpm = f"https://pool.pm/{stake_info}"

        title = "✨ Successfully submitted to the whitelist!"
        description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[<a:arrow_right:949342031166193714>{info['stake_address']}]({poolpm})**"

        fields.append(
            {
                "name": f"📋️ {type_provided} provided:",
                "value": f"`{provided_address}`",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "👤 User",
                "value": f"<@{user_id}>",
                "inline": False,
            },
        )

        if first_whitelisted:
            fields.append(
                {
                    "name": "⏱️ Set first whitelisting timestamp to:",
                    "value": f"<t:{int(first_whitelisted.timestamp())}:R>",
                    "inline": False,
                },
            )

        embed["color"] = Colors.SUCCESS

    else:
        info["stake_address"] = None
        info["ok"] = False
        info["error"] = f"Error calculating stake address: f{stake_info}."

        title = "😢 There was an error processing your address!"
        description = f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket."

        fields.append(
            {
                "name": "📋️ Provided Address",
                "value": f"`{provided_address}`",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "❗️ Error",
                "value": f"Error calculating stake address: `{stake_info}`.",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "👤 User",
                "value": f"<@{user_id}>",
                "inline": False,
            },
        )

    embed["title"] = title
    embed["description"] = description
    embed["fields"] = fields

    print(f"Adding to the whitelist: {info}")

    # get current info on the whitelist
    current_info = guild.collection("whitelist").document(user_id).get()

    if current_info.exists:
        # update the already-existign entry
        if first_whitelisted:
            info["first_whitelisted"] = first_whitelisted

        guild.collection("whitelist").document(user_id).set(info, merge=True)

        guild.collection("config").document("stats").set(
            {"n_calls": firestore.Increment(1)}, merge=True
        )

    else:
        # if it's a first addition, add the whitelist date seperately
        if not first_whitelisted:
            info["first_whitelisted"] = firestore.SERVER_TIMESTAMP
        else:
            info["first_whitelisted"] = first_whitelisted

        guild.collection("whitelist").document(user_id).set(info)

        # update the stats dictionary

        if stake_info:
            # only update user count if address was okay
            guild.collection("config").document("stats").set(
                {"n_users": firestore.Increment(1)}, merge=True
            )

        guild.collection("config").document("stats").set(
            {"n_calls": firestore.Increment(1)}, merge=True
        )

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


def manually_remove_user(body):

    # manually dd addy for user to whitelist
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

    print("Getting params")
    # parse the input parameters
    params = helper.parse_options(body["data"]["options"])
    print("PARAMS:", params)

    guild_id = body["guild_id"]
    user_id = params.get("user")["value"]

    guild = db.collection("servers").document(guild_id)

    # get current info on the whitelist
    current_info = guild.collection("whitelist").document(user_id).get()

    if current_info.exists:

        print(f"Remove user {user_id}")
        # remove the already-existign entry
        guild.collection("whitelist").document(user_id).delete()

        print("Increment n users by -1")

        guild.collection("config").document("stats").set(
            {"n_users": firestore.Increment(-1)}, merge=True
        )

        guild.collection("config").document("stats").set(
            {"n_calls": firestore.Increment(1)}, merge=True
        )

        title = f"👋 Bye!"
        description = f"Successfully removed <@{user_id}> from whitelist."
        color = Colors.SUCCESS
    else:

        title = f"🤷 User not on whitelist!"
        description = f"Could not find <@{user_id}> on the whitelist."
        color = Colors.FAIL

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": title,
        "description": description,
        "color": color,
    }

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
            "footer": {"text": "With 💖, DexoFriend"},
            "color": Colors.FAIL,
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
        "footer": {"text": "With 💖, DexoFriend"},
        "color": Colors.FAIL,
    }

    # if WL not open yet
    if not correct_channel:
        title = "😱 Whitelist features are not allowed in this channel."
        description = "Please check with the mods if you are unsure."

    elif info:
        if not info.get("error"):

            poolpm = f"https://pool.pm/{info['stake_address']}"
            title = "✨ Found whitelisted address!"
            description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[<a:arrow_right:949342031166193714>{info['stake_address']}]({poolpm})**\n\nClick the pool.pm link above and make sure it shows the Cardano wallet you intend to send ADA from to mint."
            embed["color"] = Colors.SUCCESS

        elif info.get("method") == "donation":

            title = "🎉 Almost there: Congrats Dexonaut! You've won a raffle."
            description ="... but you still need to set an address for the whitelist. Please do so with the `/whitelist` command."

        else:

            title = "😢 There was an error processing the address"
            description = f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket."

            fields.append(
                {
                    "name": "Error",
                    "value": f"`{info.get('error')}`",
                    "inline": False,
                },
            )

            fields.append(
                {
                    "name": "Stake Address",
                    "value": f"`{info.get('stake_address')}`",
                    "inline": False,
                },
            )

    elif not started:
        title = "⏰ Whitelist is not open yet."
        description = "Please check back later."

    # if WL open
    else:

        if info:
            if not info.get("error"):

                poolpm = f"https://pool.pm/{info['stake_address']}"
                title = "✨ Found whitelisted address!"
                description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[<a:arrow_right:949342031166193714>{info['stake_address']}]({poolpm})**\n\nClick the pool.pm link above and make sure it shows the Cardano wallet you intend to send ADA from to mint."
                embed["color"] = Colors.SUCCESS

            elif info.get("method") == "donation":

                title = "🎉 Almost there: Congrats Dexonaut! You've won a raffle."
                description ="... but you still need to set an address for the whitelist. Please do so with the `/whitelist` command."

            else:

                title = "😢 There was an error processing the address"
                description = f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket."

                fields.append(
                    {
                        "name": "Error",
                        "value": f"`{info.get('error')}`",
                        "inline": False,
                    },
                )

                fields.append(
                    {
                        "name": "Stake Address",
                        "value": f"`{info.get('stake_address')}`",
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


def manually_check_user(body):

    # manually dd addy for user to whitelist
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

    print("Getting params")
    # parse the input parameters
    params = helper.parse_options(body["data"]["options"])
    print("PARAMS:", params)

    guild_id = body["guild_id"]
    user_id = params.get("user")["value"]

    guild = db.collection("servers").document(guild_id)

    # get current info on the whitelist
    current_info = guild.collection("whitelist").document(user_id).get()

    fields = []
    color = Colors.FAIL

    if current_info.exists:

        print(f"Found current user info for {user_id}")
        info = current_info.to_dict()

        if not info.get("error"):

            poolpm = f"https://pool.pm/{info['stake_address']}"
            title = "✨ Found whitelisted address!"
            description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[<a:arrow_right:949342031166193714>{info['stake_address']}]({poolpm})**\n\nClick the pool.pm link above and make sure it shows the Cardano wallet you intend to send ADA from to mint."
            color = Colors.SUCCESS

        else:

            title = f"There was an error with this user's address!"
            description = f"Please see the details below"
            color = Colors.FAIL

            fields.append(
                {
                    "name": "Backend Error Message",
                    "value": f"`{info['error']}`",
                    "inline": False,
                },
            )

        fields.append(
            {
                "name": "User",
                "value": f"<@{info['user_id']}>",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "Provided Address",
                "value": f"`{info['address']}`",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "First Whitelisted",
                "value": f"<t:{int(info['first_whitelisted'].timestamp())}:F>",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": "Last Updated",
                "value": f"<t:{int(info['timestamp'].timestamp())}:F>",
                "inline": False,
            },
        )

    else:

        title = f"🤷 User not on whitelist!"
        description = f"Could not find <@{user_id}> on the whitelist."
        color = Colors.FAIL

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
    }

    print("Sending discord_update")
    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        {"embeds": [embed]},
    )

    if success:
        print("Successfully checked!")
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

    guild.collection("config").document("times").set({"begin": begin_time}, merge=True)

    print("Updated begin time!")

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": "⏰ Whitlist starting time set!",
        "color": Colors.INFO,
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

    guild.collection("config").document("times").set({"end": end_time}, merge=True)

    print("Updated end time!")

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": "🏁 Whitlist closing time set!",
        "color": Colors.INFO,
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

            info = guild.collection("config").document("times").get().to_dict()

            begin = info.get("begin")
            if not begin:
                begin = firestore.SERVER_TIMESTAMP
            elif begin > dt.datetime.now(dt.timezone.utc):
                begin = firestore.SERVER_TIMESTAMP

            guild.collection("config").document("times").set(
                {"begin": begin, "end": firestore.SERVER_TIMESTAMP}, merge=True
            )

            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoFriend"},
                "title": "📪️ Whitlist is now Closed!",
                "color": Colors.INFO,
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
                "footer": {"text": "With 💖, DexoFriend"},
                "title": "😅 Canceled! No changes made",
                "color": Colors.STATUSQUO,
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
                "footer": {"text": "With 💖, DexoFriend"},
                "color": Colors.INFO,
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

            guild.collection("config").document("times").set(
                {"begin": firestore.SERVER_TIMESTAMP, "end": None}, merge=True
            )

            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoFriend"},
                "title": "📬️ Whitlist is now open!",
                "color": Colors.INFO,
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
                "footer": {"text": "With 💖, DexoFriend"},
                "title": "😅 Canceled! No changes made",
                "color": Colors.STATUSQUO,
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
                "footer": {"text": "With 💖, DexoFriend"},
                "color": Colors.INFO,
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

    if not stats:
        stats = {"n_users": 0}

    whitelist_open, started, ended = helper.check_whitelist_open(guild)

    # get timestamps to show
    if times:
        start_timestamp = (
            f"<t:{int(times.get('begin').timestamp())}:F>"
            if times.get("begin")
            else "None set"
        )
        end_timestamp = (
            f"<t:{int(times.get('end').timestamp())}:F>"
            if times.get("end")
            else "None set"
        )

    else:
        start_timestamp, end_timestamp = "None set", "None set"

    if channel:
        active_channel = (
            f"<#{channel.get('active')}>" if channel.get("active") else "None set"
        )
    else:
        active_channel = "None set"

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": f"🤓 Whitelist is currently **{'open' if whitelist_open else 'closed'}**",
        "description": "Whitelist info for your server:",
        "color": Colors.INFO,
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

    if current_info:
        current_channel = current_info.get("active")
    else:
        current_channel = None

    new_channel = params["channel"]["value"]

    title = ""
    if current_channel:
        if current_channel == new_channel:
            title = f"🤔 Whitelist is already set to this channel."
            description = f"Channel: <#{new_channel}>"
            color = Colors.STATUSQUO

    if not title:
        guild.collection("config").document("channel").set({"active": new_channel})
        title = f"🤝 Successfully set the whitelist channel!"
        description = f"Channel: <#{new_channel}>"
        color = Colors.SUCCESS

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": title,
        "description": description,
        "color": color,
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
        color = Colors.INFO
    else:
        title = f"🤔 Whitelist was already open in all channels"
        color = Colors.STATUSQUO

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": title,
        "color": color,
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
                "footer": {"text": "With 💖, DexoFriend"},
                "title": "<a:pingpongloading:869290575118082078> Clearing whitelist.",
                "description": "This may take a few minutes. Please be patient and don't run the command again.",
                "color": Colors.INFO,
            }

            # try updating original message:
            success, response = helper.update_discord_message(
                body["message"]["application_id"],
                token,
                {"embeds": [embed], "components": []},
            )

            print("Closing WL.")
            guild.collection("config").document("times").set(
                {"begin": None, "end": firestore.SERVER_TIMESTAMP}, merge=True
            )

            print("Clearing WL")
            # remove all WL entries
            helper.clear_whitelist(guild)

            print("Clearing WL counter.")
            # clear counter
            guild.collection("config").document("stats").set({"n_users": 0}, merge=True)

            embed["title"] = "💨 Whitelist successfully cleared!"
            embed["description"] = "It was time to let go of the past."

        else:
            embed = {
                "type": "rich",
                "footer": {"text": "With 💖, DexoFriend"},
                "title": "😅 Canceled!",
                "description": "As if nothing even happened.",
                "color": Colors.STATUSQUO,
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
                "footer": {"text": "With 💖, DexoFriend"},
                "color": Colors.INFO,
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

    embed = {"type": "rich", "footer": {"text": "With 💖, DexoFriend"}, "title": ""}

    if not wl_dict:
        embed["title"] = "🤔 The whitelist is currently empty!"
        embed["description"] = "Please add users to the whitelist and try again."
        embed["color"] = Colors.RED
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

    wl_json = json.dumps(wl_dict)
    wl_bytes = str.encode(wl_json)

    embed["title"] = "📂 Attached above is the current state of your whitelist!"
    embed["color"] = Colors.INFO

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


def set_api_key(body):

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
    api_key = params["password"]["value"]

    # set api password
    guild.collection("config").document("api").set({"key": api_key}, merge=True)

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": "🔐 Successfully set API key!",
        "color": Colors.SUCCESS,
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


def verify_loader(body):

    user = body["member"]
    permissions = user["permissions"]

    lam = client("lambda")

    # check for management permissions

    new_entry = {
        "context": "followup",
        "data": {"name": "verify_followup"},
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

    return helper.loader("Loading... DexoFriend is here to help!")


def verify(body):

    # connect to firebase
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore

    import jwt
    import secrets

    print("Connecting to firestore.")
    # Use the application default credentials
    if not firebase_admin._apps:
        cert = json.loads(getenv("FIREBASE_CERT"))
        cred = credentials.Certificate(cert)
        firebase_app = firebase_admin.initialize_app(cred)

    db = firestore.client()

    guild_id = body["guild_id"]

    user = body["member"]
    user_id = user["user"]["id"]

    user_info = db.collection("users").document(user_id).get().to_dict()
    wallets = []

    issue_new_token = False
    if user_info:
        wallets = user_info.get("stake_addresses")
        last_exp = user_info.get("jwt_exp")
        if last_exp:
            if last_exp - dt.datetime.now(tz=dt.timezone.utc) < dt.timedelta(
                minutes=10
            ):
                issue_new_token = True

    if issue_new_token:

        token = secrets.token_urlsafe(16)

        # create JWT with the token
        expiration = dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(
            days=1, minutes=10
        )  # expires in 1hr
        payload = {
            "user_id": user_id,
            "avatar": user["user"]["avatar"],
            "name": user["user"]["username"],
            "disc": user["user"]["discriminator"],
            "exp": expiration,
            "iss": "DexoFriend",
            "guild": guild_id,
        }
        encoded = jwt.encode(payload, token)

        # add token info to firebase

        db.collection("users").document(user_id).set(
            {
                "last_jwt": encoded,
                "last_secret": token,
                "avatar": user["user"]["avatar"],
                "username": user["user"]["username"],
                "discriminator": user["user"]["discriminator"],
                "jwt_exp": expiration,
                "from_guild": guild_id,
                "last_application_id": body["original_body"]["application_id"],
                "last_discord_token": body["original_body"]["token"],
                "last_discord_call": firestore.SERVER_TIMESTAMP,
            },
            merge=True,
        )

    else:
        # give old token
        encoded = user_info["last_jwt"]

        # update database with discord call
        db.collection("users").document(user_id).set(
            {
                "from_guild": guild_id,
                "last_application_id": body["original_body"]["application_id"],
                "last_discord_token": body["original_body"]["token"],
                "last_discord_call": firestore.SERVER_TIMESTAMP,
            },
            merge=True,
        )

    if wallets:
        description = f"FYI: You've already connected {len(wallets)} wallets."
    else:
        description = f"FYI: You haven't connected any wallets yet."

    # return URL with JWT attached
    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": "🧑‍🚀 Please click the button below to manage your wallets!",
        "description": description,
        # "description": f"[<a:arrow_right:949342031166193714> Click me!](https://dev-api.dexoworlds.com/verify/{user_id}/connect?token={encoded})",
        "color": Colors.INFO,
    }

    components = [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "label": "To the Portal",
                    "style": 5,
                    "url": f"https://api.dexoworlds.com/verify/{user_id}/connect?token={encoded}",
                    "emoji": {"id": None, "name": "🪐"},
                },
            ],
        }
    ]

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        {"embeds": [embed], "components": components},
    )

    if success:
        print(f"Successfully sent update: {embed}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None


def add_holder_role(body):

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

    roles = {}
    for role in guild.collection("roles").stream():
        roles[role.id] = role.to_dict()

    new_role = params["role"]["value"]
    new_policy = params["policy_id"]["value"]

    title = ""
    if new_role in roles.keys():
        title = f"Updating the role policy ID."
    else:
        title = f"Creating new policy verification."

    description = f"Role: <@&{new_role}> will be assigned to policy:\n`{new_policy}`"
    color = Colors.STATUSQUO

    # update policy ID in database
    guild.collection("config").document("roles").set({new_role: new_policy}, merge=True)

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": title,
        "description": description,
        "color": color,
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


def view_holder_roles(body):

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

    roles = guild.collection("config").document("roles").get().to_dict()

    fields = []
    if not roles:
        title = "There are not currently any roles for holders set up."
        description = "You can use the `add_holder_role` to set one up."
        color = Colors.FAIL
    else:
        title = f"There are {len(roles)} holder role conditions set up."
        description = f"Details below:"
        color = Colors.INFO
        for k, v in roles.items():
            fields.append(
                {
                    "name": f"Policy ID: `{v}`",
                    "value": f"Role: <@&{k}>",
                    "inline": False,
                }
            )

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
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


def remove_holder_role(body):

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

    roles = guild.collection("config").document("roles").get().to_dict()

    role_to_remove = params["role"]["value"]

    title = ""
    if role_to_remove not in roles.keys():
        title = f"Role is not currently assigned to any policy ID."
        description = "You can add a role rule with the `/add_holder_role` command."
        color = Colors.FAIL
    else:
        title = f"Successfully removed role from holder verification."
        description = f"Role: <@&{role_to_remove}> will no longer be assigned to holders of the policy ID \n`{roles[role_to_remove]}`"
        color = Colors.SUCCESS

        # remove the role / policy ID in database
        del roles[role_to_remove]
        guild.collection("config").document("roles").set(roles)

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": title,
        "description": description,
        "color": color,
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


def donate(body):
    """Donate spots to the whitelist."""

    # check the whitelist
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore

    import base64
    from math import floor, ceil

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

    n_spots = params.get("how_many")["value"]
    role = params.get("role")["value"] if params.get("role") else None
    message = params.get("message")["value"] if params.get("message") else None
    winner_role = params.get("role")["value"] if params.get("role") else None

    print("GOT:", n_spots, role, message)

    # generate a unique ID for the giveaway, follow the following to get a base64 code
    # https://stackoverflow.com/questions/55354229/converting-an-integer-value-to-base64-and-then-decoding-it-to-get-a-plaintext
    donation_start = dt.datetime.now(dt.timezone.utc)
    donation_end = donation_start + dt.timedelta(hours=72)

    donation_int = int(str(guild_id) + str(int(donation_start.timestamp())))

    number_bytes = donation_int.to_bytes(
        (donation_int.bit_length() + 7) // 8, byteorder="big"
    )
    encoded = base64.urlsafe_b64encode(number_bytes)
    donation_id = encoded.decode()

    print(f"donation id: {donation_id}")

    # set up number of spots for dexo holders and starlord holders
    n_worlds = floor(n_spots / 2)
    n_stars = ceil(n_spots / 2)

    # get guild info
    guild_info = helper.get_guild_info(guild_id)
    print(guild_info)
    guild_name = guild_info.get("name")
    icon = guild_info.get("icon")
    system_channel_id = guild_info.get("system_channel_id")

    # generate server invite link
    invite = helper.create_channel_invite(system_channel_id)
    print(f"Invite info:", invite)
    invite_url = f"https://discord.gg/{invite.get('code')}"

    # get dexobot settings
    dexobot_config = db.collection("config").document("channels").get().to_dict()

    donation_start = dt.datetime.now(dt.timezone.utc)
    donation_end = donation_start + dt.timedelta(hours=72)

    # set up mention rules
    mentions = {
        "roles": [
            dexobot_config.get("starlords_role"),
            dexobot_config.get("holders_role"),
        ]
    }

    # send discord messages (with dexobot!)
    content = (
        f"<@&{dexobot_config.get('holders_role')}> WL donation from {guild_name}!"
    )

    embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": f"{n_worlds} WL spot{'s' if n_worlds > 1 else ''} for DexoWorld Holders at {guild_name}!",
        "description": "Use the buttons below to enter. It's helpful to join their server before the raffle ends, just in case you need to get a special role assigned.",
        "color": 0xFF5ACD,
        "thumbnail": {"url": f"https://cdn.discordapp.com/icons/{guild_id}/{icon}.png"},
        "fields": [
            {
                "name": "Ends",
                "value": f"<t:{int(donation_end.timestamp())}:R>",
                "inline": False,
            },
            {
                "name": "Server",
                "value": f"`{guild_name}`",
                "inline": False,
            },
            {
                "name": "Server Invite Link",
                "value": f"[Click here to join the server]({invite_url})",
                "inline": False,
            },
        ],
    }

    if message:
        embed["fields"].append(
            {
                "name": f"Message from {guild_name} team",
                "value": message,
                "inline": False,
            }
        )

    holder_button = [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "label": "Enter",
                    "style": 1,
                    "custom_id": f"enter-h-{donation_id}",
                    "emoji": {"id": None, "name": "✨"},
                },
            ],
        }
    ]

    starlord_button = [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "label": "Enter",
                    "style": 1,
                    "custom_id": f"enter-s-{donation_id}",
                    "emoji": {"id": None, "name": "✨"},
                },
            ],
        }
    ]

    # send the discord message
    if n_worlds:
        holders_message = helper.post_channel_message(
            {
                "content": content,
                "embeds": [embed],
                "components": holder_button,
                "allowed_mentions": mentions,
            },
            dexobot_config.get("holders_channel"),
            getenv("DEXOBOT_TOKEN"),
        )
    else:
        holders_message = None

    embed[
        "title"
    ] = f"{n_stars} WL spot{'s' if n_stars > 1 else ''} for Dexo Starlords at {guild_name}!"
    content = f"<@&{dexobot_config.get('starlords_role')}> WL donation from {guild_name}!"

    starlord_message = helper.post_channel_message(
        {
            "content": content,
            "embeds": [embed],
            "components": starlord_button,
            "allowed_mentions": mentions,
        },
        dexobot_config.get("starlords_channel"),
        getenv("DEXOBOT_TOKEN"),
    )

    # add info to database
    info = {
        "done": False,
        "guild_id": guild_id,
        "guild_name": guild_name,
        "donation_begin": donation_start,
        "donation_end": donation_end,
        "n_spots": n_worlds + n_stars,
        "n_worlds": n_worlds,
        "n_stars": n_stars,
        "winner_role": winner_role,
        "message": "thanks!",
        "invite_url": invite_url,
        "holders_message": holders_message,
        "starlords_message": starlord_message,
        "icon_url": f"https://cdn.discordapp.com/icons/{guild_id}/{icon}.png",
    }

    db.collection("donations").document(donation_id).set(info, merge=True)

    success_embed = {
        "type": "rich",
        "footer": {"text": "With 💖, DexoFriend"},
        "title": "Donation successful!",
        "description": "Winners of the DexoFriend raffle will be automatically added to your whitelist in 72h. Thank you so much for your donation and for supporting DexoFriend and cardano development. If you'd like to stay in the loop on further developments, follow me (pastapleas3) on Twitter! If you have questions or feature requests, please contact me on Twitter or Discord.",
        "color": Colors.INFO,
        "fields": [
            {
                "name": "Twitter",
                "value": "[pastapleas3](https://twitter.com/pastapleas3)",
                "inline": False,
            },
            {
                "name": "Discord",
                "value": "pastaplease#2823",
                "inline": False,
            },
        ],
    }

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"],
        body["original_body"]["token"],
        {"embeds": [success_embed], "flags": 64},
    )

    if success:
        print(f"Successfully sent update: {success_embed}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None


def help(body):

    user = body["member"]
    permissions = user["permissions"]

    # check for management permissions
    print("Checking authorization...")
    authorized = helper.permissions.is_manager(permissions)
     
    if not authorized:
        # if normal user, return standard help

        embed = {
            "type": "rich",
            "footer": {"text": "With 💖, DexoFriend"},
            "title": "We're here to help! Please read the following carefully.",
            "description": "In order to run any commands, you must first type the backslash `/` character, and scroll through the list of commands (or start typing) to find the one you want.\nCheck out the information below, and reach out if you still have questions.",
            "color": Colors.INFO,
            "fields": [
                {
                    "name": "/whitelist",
                    "value": "After activating the `/whitelist` command, you should see an `Address:` field appear. Paste a Cardano address, stake address, or ADA Handle. Then press enter! Run this again to overwrite the previous address you added.",
                    "inline": False,
                },
                {
                    "name": "/check_whitelist",
                    "value": "Use `/check_whitelist` to check if you've already submitted an address, and if so, to confirm which one. This command takes no parameters.",
                    "inline": False,
                },
                {
                    "name": "/verify",
                    "value": "Provides a link to our verification portal where you can connect wallets in order to get special roles for holders if the mods have set them up. These wallets will carry over across all servers that use DexoFriend!",
                    "inline": False,
                },
                {
                    "name": "Want DexoFriend in your server?",
                    "value": "[Check out the documentation here!](https://api.dexoworlds.com/dexofriend/docs/)",
                    "inline": False,
                },
                {
                    "name": "Twitter Help",
                    "value": "[@dexoworlds](https://twitter.com/dexoworlds)",
                    "inline": False,
                },
                {
                    "name": "DexoWorlds Discord Server",
                    "value": "[Come hang!](https://discord.gg/beaUBWhXaq) (We also have a channel just for DexoFriend!)",
                    "inline": False,
                },
            ],
        }

    else:
        # if a mod

        embed = {
            "type": "rich",
            "footer": {"text": "With 💖, DexoFriend"},
            "title": "Hello Server mod! You're seeing this special help message since you have the 'manage channels' permission.",
            "description": "For all the details about how to use DexoFriend, please see our official documentation linked below.\nAnd please consider donating WL spots if you haven't already. Thanks!",
            "color": Colors.INFO,
            "fields": [
                {
                    "name": "Official DexoFriend Docs",
                    "value": "[Check out the documentation here!](https://api.dexoworlds.com/dexofriend/docs/)",
                    "inline": False,
                },
                {
                    "name": "Twitter Help",
                    "value": "[@dexoworlds](https://twitter.com/dexoworlds)",
                    "inline": False,
                },
                {
                    "name": "DexoWorlds Discord Server",
                    "value": "[Come hang!](https://discord.gg/beaUBWhXaq) (We also have a channel just for DexoFriend!)",
                    "inline": False,
                },
            ],
        }

    return {"embeds": [embed], "flags": 64}