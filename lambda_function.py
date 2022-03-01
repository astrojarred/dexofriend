import os
import traceback

from nacl.signing import VerifyKey

from dexobot import commands

PUBLIC_KEY = os.getenv(
    "DISCORD_APP_PUBLIC_KEY"
)  # found on Discord Application -> General Information page
if not PUBLIC_KEY:
    raise Exception("No Discord app public key found!")

PING_PONG = {"type": 1}
RESPONSE_TYPES = {
    "PONG": 1,
    "ACK_NO_SOURCE": 2,
    "MESSAGE_NO_SOURCE": 3,
    "MESSAGE_WITH_SOURCE": 4,
    "ACK_WITH_SOURCE": 5,
}


def verify_signature(event):
    raw_body = event.get("rawBody")
    auth_sig = event["params"]["header"].get("x-signature-ed25519")
    auth_ts = event["params"]["header"].get("x-signature-timestamp")

    message = auth_ts.encode() + raw_body.encode()
    verify_key = VerifyKey(bytes.fromhex(PUBLIC_KEY))
    verify_key.verify(message, bytes.fromhex(auth_sig))  # raises an error if unequal


def ping_pong(body):
    if body.get("type") == 1:
        return True
    return False


def lambda_handler(event, context):
    print(f"event {event}")  # debug print

    # check if a this is a followup call
    try:
        if event.get("context") != "followup":  # and (not is_component_click):
            # verify the signature
            try:
                verify_signature(event)

            except Exception as e:
                raise Exception(f"[UNAUTHORIZED] Invalid request signature: {e}")
        else:
            
            if event.get("detail") == "keep-warm":
                print("Keep warm!")
                from dexobot.helper import keep_warm
                keep_warm()
                return {"response": "keeping warm!"}

            print("Followup event!")

        if event.get("context") != "followup":
            # check if message is a ping
            body = event.get("body-json")
            if ping_pong(body):
                return PING_PONG

            body["invoked-function-arn"] = context.invoked_function_arn
        else:
            body = event
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[ERROR]\n{e}\n\nTraceback:\n{tb}")
        return {
            "type": 4,
            "data": {
                "content": f"There was an error during initialization!\n```python\n{e}\n\n# Traceback:\n{tb}```", "flags": 64
            }
        }


    # run the command
    try:
        return commands.check_command(body)
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[ERROR]\n{e}\n\nTraceback:\n{tb}")
        return {
            "type": 4,
            "data": {
                "content": f"There was an error!\n```python\n{e}\n\n# Traceback:\n{tb}```", "flags": 64
            }
        }

