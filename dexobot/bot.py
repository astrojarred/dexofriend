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

    #if not any(x in whitelist_role_ids for x in user_roles):
    #    error_title = "<:sadfrog:898565061239521291> You don't have permission to whitelist."
    #    error_message = "Sorry, the whitelist function is for certain roles only. Please see <#900299272996671518> for more information.\nThank you for your enthusiasm, and stay tuned!"
    if address[:4] == "addr" and len(address) < 58:
        error_title = "<:sadfrog:898565061239521291> There was an error processing your address."
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

    # add timestamp
    info["timestamp"] = firestore.SERVER_TIMESTAMP  # dt.datetime.now(dt.timezone.utc)

    # check the cardano address
    provided_address = info["address"]
    address, stake_info, type_provided = helper.parse_address(provided_address)
    # got_stake, stake_info = helper.get_stake_address(info["address"])

    fields = []

    if stake_info:
        info["stake_address"] = stake_info
        info["ok"] = True
        info["error"] = None

        poolpm = f"https://pool.pm/{stake_info}"

        embed = {
            "type": "rich",
            "title": "✨ Successfully submitted to the whitelist!",
            "description": f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[{info['stake_address']}]({poolpm})**",
            # "author": {"name": "Happy Hoppers Main Drop"},
            "footer": {"text": "With 💖, DexoBot"},
        }

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

        embed = {
            "type": "rich",
            "title": "😢 There was an error processing your address!",
            "description": f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket.",
            # "author": {"name": "Happy Hoppers Main Drop"},
            "footer": {"text": "With 💖, DexoBot"},
        }

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

    
    embed["fields"] = fields

    print(f"Adding to the whitelist: {info}")

    guild = db.collection("servers").document(guild_id)

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

    print("Sending discord_update")
    success, response = helper.update_discord_message(
        body["original_body"]["application_id"], body["original_body"]["token"], {"embeds": [embed]}
    )

    if success:
        print("Successfully added!")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None

"""
def check_whitelist(body):

    user = body["member"]
    user_id = user["user"]["id"]

    # get valid roles
    whitelist_role_string = getenv("WHITELIST_ROLES")
    assert whitelist_role_string
    whitelist_role_ids = json.loads(whitelist_role_string)

    user_roles = user["roles"]

    # posted_channel = body.get("channel_id")
    # whitelist_channels = ["907009511204728983"]

    # check for errors:
    error_message = None

    # if not posted_channel in whitelist_channels:
    #     error_message = f"Please try again in the bot channel: "
    #     for channel_id in whitelist_channels:
    #         error_message += f"<#{channel_id}> "
    if not any(x in whitelist_role_ids for x in user_roles):
        error_title = "<:sadfrog:898565061239521291> You don't have permission to whitelist."
        error_message = "Sorry, the whitelist function is for certain roles only. Please see <#900299272996671518> for more information.\nThank you for your enthusiasm, and stay tuned!"

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

    current_whitelist = getenv("CURRENT_WHITELIST")

    assert current_whitelist

    info = body["whitelist_info"]

    info = db.collection(current_whitelist).document(info["user_id"]).get().to_dict()
    print(info)

    # check if minter is online
    minter_online, last_online = helper.check_minter_status(
        db, f"{current_whitelist}_fast"
    )

    print(f"Minter online: {minter_online}, last active {last_online}")

    fields = []
    embed = {
        "type": "rich",
        # "author": {"name": "Happy Hoppers Main Drop"},
        "footer": {"text": "With 💖, DexoBot"},
    }

    if not minter_online:

        if info:
            if not info["error"]:
                
                poolpm = f"https://pool.pm/{info['stake_address']}"
                title = "<:DexoBot:913093127504535582> Found whitelisted address!"
                description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[{info['stake_address']}]({poolpm})**\n\nClick the pool.pm link above and make sure it shows the Cardano wallet you intend to send ADA from to mint."

            else:

                title = "<:sadfrog:898565061239521291> There was an error processing the address"
                description =  f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket."

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
            title = "<:sadfrog:898565061239521291> Unable to find this user on the whitelist."
            description = "Try adding youself with the 'whitelist' command."

    else:
        # get window information
        # --> FOR A DROP WITH TIME WINDOWS
        windows = helper.get_time_windows(db, f"{current_whitelist}_windows")
        # is_changing = helper.check_window_changing(db, f"{current_whitelist}_windows")
        drop_done = helper.check_drop_over(db, f"{current_whitelist}_fast")

        has_windows = True
        try:
            (
                current_deadline_start,
                current_deadline_end,
                current_window_id,
            ) = helper.get_current_deadline(windows)
        except IndexError as e: 
            has_windows = False

        check_eligibility = False
        
        if info:
            if not info["error"]:
                poolpm = f"https://pool.pm/{info['stake_address']}"

                title = "<:DexoBot:913093127504535582> Found whitelisted address!"
                description = f"[**💢 Check your address on pool.pm 💢**]({poolpm})\n**[{info['stake_address']}]({poolpm})**\nCheck the link above and make sure it shows the Cardano wallet you intend to send ADA from to mint."

                check_eligibility = True
            else:
                title = "<:sadfrog:898565061239521291> There was an error processing the address"
                description =  f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm. For further support, please copy or screenshot this error message and open a support ticket."
                fields.append(
                    {
                        "name": "Error",
                        "value": f"`{info['error']}`",
                        "inline": False,
                    },
                )

        else:
            title = "<:sadfrog:898565061239521291> Unable to find this user on the whitelist."
            description = "Try adding youself with the 'whitelist' command."


        eligibility_message = ""
        # if not has_windows or drop_done:
        if drop_done:
            # minting is over
            title = "🙏<:DexoBot:913093127504535582> The drop is over. Thank you so much for your support!"
        elif check_eligibility:
            # check if final jeopardy
            # --> FOR A DROP WITH WINDOWS AND FINAL JEOPARDY
            # '''
            is_final_jeopardy, final_jeopardy_timestamp = helper.is_final_jeopardy(
                db, f"{current_whitelist}_fast"
            )

            not_minted_in_final_jeopardy, selected_in_window, not_minted_yet, whitelisted_before_window = helper.validate_eligibility(db, current_whitelist, info, current_deadline_start, current_window_id, is_final_jeopardy, final_jeopardy_timestamp)

            can_mint = not_minted_in_final_jeopardy and selected_in_window and not_minted_yet and whitelisted_before_window

            over_for_you = False
            mint_right_now = False

            if is_final_jeopardy:

                if can_mint:
                    mint_right_now = True
                    status_description = f"You were randomly selected to mint another hopper during this bonus window!"
                elif not not_minted_in_final_jeopardy:
                    over_for_you = True
                    status_description = f"You've already minted during the bonus window period. Thanks for your support!\n"
                elif not selected_in_window:
                    status_description = f"You were not randomly selected to mint a hopper during this bonus window. Come back and check again during the next window."
            else:
                if can_mint:
                    mint_right_now = True
                    status_description = f"Thank you for whitelisting!\nYou are guaranteed a Hopper until the end of the current window.\n"
                elif not not_minted_yet:
                    status_description = f"It looks like you've already minted during this whitelist window, but check back at the end of the current window to see if you're eligible for another mint."
                else:
                    status_description = f"Thank you for whitelisting!\nYou are not eligible right now, but check back at the end of the current window to see if you're eligible for a mint."
            
            

            # '''
            # -->FOR A SIMPLE 1 / WL drop with not windows or lottery
            not_minted_yet = helper.has_not_minted_yet(info.get("stake_address"), db, f"{current_whitelist}_tx_out", current_deadline_start, info.get("user_id"), max_txs_allowed=1)

            if not_minted_yet:
                # eligibility_message = f"**YOU CAN MINT!**\nThank you for whitelisting!\nYou are guaranteed a Hopper until the end of the current window (appx. {helper.date_countdown(current_deadline_end)} left).\n"
                title = "<:DexoBot:913093127504535582> You can mint now!"
            else:
                # eligibility_message = f"**YOU'VE ALREADY MINTED!** This drop is only one per person.\nThank you so much for participating!"
                title = "🙏 You have already minted a Hopper. Thank you so much for your support!"

            fields.append(
                {
                    "name": "Drop ending in",
                    "value": f"`{helper.date_countdown(current_deadline_end)}`",
                    "inline": True,
                },
            )


            # '''
            # --> FOR A DROP WITH WINDOWS AND FINAL JEOPARDY
            title = "<:DexoBot:913093127504535582> You can mint now!" if mint_right_now else "⏰ Please wait to mint."
            title = title if not over_for_you else "🙏 This drop is done for you. Thank you!"

            # check if window is changing
            title = title if not is_changing else "⏰ Please check back in a few minutes! Minter is preparing for the next window."
            status_description = status_description if not is_changing else "Window change. Please be patient and check back in a few minutes!"


            fields.append(
                {
                    "name": "Current status",
                    "value": status_description,
                    "inline": True,
                },
            )

            # if not is_changing:
                 fields.append(
                     {
                         "name": "Current window",
                         "value": f"`#{current_window_id}`",
                         "inline": True,
                     },
                 )
             
                 fields.append(
                     {
                         "name": "Next window starting in",
                         "value": f"`{helper.date_countdown(current_deadline_end)}`",
                         "inline": True,
                     },
                 )
            # '''

    embed["title"] = title
    embed["description"] = description
    embed["fields"] = fields

    success, response = helper.update_discord_message(
        body["original_body"]["application_id"], body["original_body"]["token"], {"embeds": [embed]}
    )

    if success:
        print(f"Successfully sent update: {embed}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return None

def add_wings(body):

    lam = client("lambda")

    new_data = {
        "context": "followup",
        "data": {"name": "add_wings_followup"},
        "original_body": body,
    }

    lam.invoke(
        FunctionName=body["invoked-function-arn"],
        InvocationType="Event",
        Payload=json.dumps(new_data),
    )

    return helper.loading_snail(text=f"Crunching the numbers...", public = False)


def add_wings_followup(body):

        
    # connect to our db
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

    new_body = body.get("original_body")
    params = helper.parse_options(new_body["data"]["options"])

    # get user info
    user = body["original_body"]["member"]
    user_id = user["user"]["id"]

    # check the cardano address
    address = params["address"]["value"]
    got_stake, stake_info = helper.get_stake_address(address)

    # get selected NFT info
    hopper_id = params["hopper_id"]["value"]
    swimmer_id = params["swimmer_id"]["value"]

    fields = []
    in_error = False

    # check validity of all inputs
    if not got_stake:

        in_error = True

        embed = {
            "type": "rich",
            "title": "<:sadfrog:898565061239521291> There was an error processing your address!",
            "description": f"Most likely you have provided an invalid address. Try resubmitting your address or checking if it looks correct on pool.pm.\nFor further support, please copy or screenshot this error message and open a support ticket.",
            # "author": {"name": "Happy Hoppers Main Drop"},
            "footer": {"text": "With 💖, DexoBot"},
        }

        fields.append(
            {
                "name": "Address",
                "value": f"`{address}`",
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

    elif (hopper_id > 11100) or (hopper_id < 1):

        in_error = True

        embed = {
            "type": "rich",
            "title": "<:sadfrog:898565061239521291> The Hopper ID must be between 1 and 11100!",
            "description": f"1/1s cannot have wings added to them either.",
            # "author": {"name": "Happy Hoppers Main Drop"},
            "footer": {"text": "With 💖, DexoBot"},
        }

        fields.append(
            {
                "name": "Hopper ID",
                "value": f"`{hopper_id}`",
                "inline": False,
            },
        )

    elif (swimmer_id < 1076) or (swimmer_id > 1111):

        in_error = True

        embed = {
            "type": "rich",
            "title": "<:sadfrog:898565061239521291> The Swimmer ID given is not a Gold Swimmer!",
            "description": f"Hint: Only swimmers with IDs between 1077 and 1111.",
            # "author": {"name": "Happy Hoppers Main Drop"},
            "footer": {"text": "With 💖, DexoBot"},
        }

        fields.append(
            {
                "name": "Swimmer ID",
                "value": f"`{swimmer_id}`",
                "inline": False,
            },
        )

    if in_error:

        embed["fields"] = fields

        success, response = helper.update_discord_message(
            new_body["application_id"], new_body["token"], {"embeds": [embed]}
        )

        if success:
            print(f"Successfully sent update: {embed}")
        else:
            print(f"ERROR: Could not update discord messages: {response}")

        return

    # calculate price
    # 10 + ((swimmerID - 1076)/10) + (hopperID / 1000000)
    # ada_to_send = 10 + ((swimmer_id - 1076)/10) + (hopper_id / 1000000)
    ada_to_send = 10 + (hopper_id / 1000000)

    # LATER: Check with Blockfrost to confirm token ownership and that they're not used already.
    swimmer_policy = "00ff3ae62bd2d44dab9ad8ff3eed7770201840784bd05cd524856520"
    hopper_policy = "11ff0e0d9ad037d18e3ed575cd35a0513b8473f83008124db89f1d8f"

    api = BlockFrostApi(
        project_id=getenv("BLOCKFROST_ID"),  # or export environment variable BLOCKFROST_PROJECT_ID
    )

    swimmer_asset = f"SwankySwimmer{str(swimmer_id).zfill(4)}"
    hopper_asset = f"HappyHopper{str(hopper_id).zfill(5)}"

    try:
        swimmer_info = api.asset(swimmer_policy + swimmer_asset.encode("utf-8").hex())
        current_result = swimmer_info
        print(f"Swimmer info: {swimmer_info}")

        hopper_info = api.asset(hopper_policy + hopper_asset.encode("utf-8").hex())
        current_result = hopper_info
        print(f"Hopper info: {hopper_info}")

        swimmer_owner = api.asset_addresses(swimmer_policy + swimmer_asset.encode("utf-8").hex())[0].address
        current_result = swimmer_owner
        print(f"Swimmer owner: {swimmer_owner}")

        hopper_owner = api.asset_addresses(hopper_policy + hopper_asset.encode("utf-8").hex())[0].address
        current_result = hopper_owner
        print(f"Hopper owner: {hopper_owner}")


    except ApiError as e:
        embed = {
            "type": "rich",
            "title": "<:sadfrog:898565061239521291> Error reading wallet.",
            "description": f"Please try again, or screenshot this and contact pastaplease.",
            "footer": {"text": "With 💖, DexoBot"},
        }

        fields.append(
            {
                "name": f"Error message:",
                "value": f"`{e}`\n`{current_result}`",
                "inline": False,
            },
        )

        embed["fields"] = fields

        success, response = helper.update_discord_message(
            new_body["application_id"], new_body["token"], {"embeds": [embed]}
        )

        if success:
            print(f"Successfully sent update: {embed}")
        else:
            print(f"ERROR: Could not update discord messages: {response}")

        return


    swimmer_stake_calc_ok, swimmer_stake = helper.get_stake_address(swimmer_owner)
    hopper_stake_calc_ok, hopper_stake = helper.get_stake_address(hopper_owner)

    swimmer_stake_ok = swimmer_stake == stake_info
    hopper_stake_ok = hopper_stake == stake_info

    if not swimmer_stake_ok or not hopper_stake_ok:
        if hopper_stake_ok:
            message = f"The address given does not hold Swanky Swimmer {swimmer_id}."
        elif swimmer_stake_ok:
            message = f"The address given does not hold Happy Hopper {hopper_id}."
        else:
            message = f"The address given does not hold Happy Hopper {hopper_id} nor Swanky Swimmer {swimmer_id}."

        embed = {
            "type": "rich",
            "title": "<:sadfrog:898565061239521291> " + message,
            "description": f"Check out the wallets below to see which ones hold each token.",
            "footer": {"text": "With 💖, DexoBot"},
        }

        fields.append(
            {
                "name": f"Provided wallet",
                "value": f"[Pool.pm: {stake_info}](https://pool.pm/{stake_info})",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": f"Hopper {hopper_id} wallet",
                "value": f"[Pool.pm: {hopper_stake}](https://pool.pm/{hopper_stake})",
                "inline": False,
            },
        )

        fields.append(
            {
                "name": f"Swimmer {swimmer_id} wallet",
                "value": f"[Pool.pm: {swimmer_stake}](https://pool.pm/{swimmer_stake})",
                "inline": False,
            },
        )

        embed["fields"] = fields

        success, response = helper.update_discord_message(
            new_body["application_id"], new_body["token"], {"embeds": [embed]}
        )

        if success:
            print(f"Successfully sent update: {embed}")
        else:
            print(f"ERROR: Could not update discord messages: {response}")

        return


    # If everything ok: return price
    with open("HappyHoppersS1.json", "r") as f:
        meta = json.load(f)[str(hopper_id)]

    embed = {
        "type": "rich",
        "title": "You can add wings!",
        "thumbnail": {
            "url": "https://" + urllib.parse.quote(f"happyhoppers-s1.s3.us-east-2.amazonaws.com/HappyHoppersS1/{meta['image_name']}")
        },
        "description": f"Please send exactly `{ada_to_send:.6f}` ADA **AND your gold** `SwankySwimmer{swimmer_id}` to the address below.\n**DO NOT SEND THE HOPPER!**",
        "footer": {"text": "With 💖, DexoBot"},
    }

    fields.append(
        {
            "name": "Address",
            "value": f"`{getenv('WINGS_ADDRESS')}`",
            "inline": False,
        },
    )

    fields.append(
        {
            "name": "Hopper ID",
            "value": f"`{hopper_id}`",
            "inline": False,
        },
    )

    fields.append(
        {
            "name": "Swimmer ID",
            "value": f"`{swimmer_id}`",
            "inline": False,
        },
    )

    embed["fields"] = fields

    success, response = helper.update_discord_message(
        new_body["application_id"], new_body["token"], {"embeds": [embed]}
    )

    if success:
        print(f"Successfully sent update: {embed}")
    else:
        print(f"ERROR: Could not update discord messages: {response}")

    return




"""