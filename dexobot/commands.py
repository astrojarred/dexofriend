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
    "set_channel": bot_manual("set_channel", bot.set_channel, bot.admin_loader),
    "remove_channel": bot_manual("remove_channel", bot.remove_channel, bot.admin_loader),
    "clear_whitelist": bot_manual("clear_whitelist", bot.clear_whitelist, bot.admin_loader),
    "export_whitelist": bot_manual("export_whitelist", bot.export_whitelist, bot.admin_loader),
    "manually_add_user": bot_manual("manually_add_user", bot.manually_add_user, bot.admin_loader),
    "manually_remove_user": bot_manual("manually_remove_user", bot.manually_remove_user, bot.admin_loader),
    "manually_check_user": bot_manual("manually_check_user", bot.manually_check_user, bot.admin_loader),
    "set_api_key": bot_manual("set_api_key", bot.set_api_key, bot.admin_loader),
    "verify": bot_manual("verify_loader", bot.verify_loader),
    "verify_followup": bot_manual("verify", bot.verify),
    "add_holder_role": bot_manual("add_holder_role", bot.add_holder_role, bot.admin_loader),
    "view_holder_roles": bot_manual("view_holder_roles", bot.view_holder_roles, bot.admin_loader),
    "remove_holder_role": bot_manual("remove_holder_role", bot.remove_holder_role, bot.admin_loader),
    "donate": bot_manual("donate", bot.donate, bot.admin_loader),
    "help": bot_manual("help", bot.help),
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
