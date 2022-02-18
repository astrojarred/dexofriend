from dexobot import bot
from dexobot.command_types import bot_command, bot_embed, bot_followup, bot_manual

ALL_COMMANDS = {
    "constant": bot_manual("constant", bot.constant),
    "whitelist": bot_manual("whitelist", bot.whitelist),
    "check_whitelist": bot_manual("check_whitelist", bot.check_whitelist),
    "add_whitelist_entry": bot_manual("add_whitelist_entry", bot.add_whitelist_entry),
    "check_whitelist_followup": bot_manual("check_whitelist_followup", bot.check_whitelist_followup),
    "set_start": bot_manual("set_start", bot.set_start_time, bot.admin_loader),
    "set_end": bot_manual("set_end", bot.set_end_time, bot.admin_loader),
    "close_whitelist_now": bot_manual("close_whitelist_now", bot.close_whitelist_now, bot.admin_loader),
    "open_whitelist_now": bot_manual("open_whitelist_now", bot.open_whitelist_now, bot.admin_loader),
    "info": bot_manual("info", bot.get_whitelist_info, bot.admin_loader),
    "set_channel": bot_manual("set_channel", bot.set_channel, bot.admin_loader)
}

def check_command(body):

    command_name = body["data"].get("name")

    if not command_name:
        command_name = body["message"]["interaction"].get("name")

    command = ALL_COMMANDS.get(command_name)

    if command:
        return command.run(body)

    else:
        return {
            "type": 4,
            "data": {
                "content": f"Command does not exist.", "flags": 64
            }
        }
