from dexobot.helper import send_discord_followup


class bot_command:
    """Plaintext/markup text only response"""

    def __init__(self, name, action, response_type=4):

        self.name = name
        self.action = action
        self.response_type = response_type

    def run(self, body):

        # check that command is correct one
        if body["data"]["name"] == self.name:

            # run command
            print(f"Running command: {self.name}")
            response = self.action(body)

            return {
                "type": self.response_type,
                "data": {
                    "content": response
                }
            }

class bot_embed:
    """Only one embed as response"""

    def __init__(self, name, action, response_type=4):

        self.name = name
        self.action = action
        self.response_type = response_type

    def run(self, body):

        # check that command is correct one
        if body["data"]["name"] == self.name:

            # run command
            print(f"Running command: {self.name}")
            response = self.action(body)

            return {
                "type": self.response_type,
                "data": {
                    "embeds": [response]
                }
            }

class bot_manual:
    """Manually return data fields"""

    def __init__(self, name, action, loader=None, response_type=4):

        self.name = name
        self.action = action
        self.loader = loader
        self.response_type = response_type

    def run(self, body):

        # check for loader

        already_responded = False
        if self.loader:
            if body.get("context") != "followup":
                print(f"Returning Loader for {self.name}")
                data = self.loader()
                already_responded = True

        if not already_responded:
            # run command
            print(f"Running command: {self.name}")
            data = self.action(body)

            if isinstance(data, bool):
                return

        response = {
            "type": self.response_type,
            "data": data,
        }

        print(f"Returning {response}")
        return response

class bot_followup:
    """A followup post after initial response has already been sent"""

    def __init__(self, name, action, response_type=4):

        self.name = name
        self.action = action
        self.response_type = response_type

    def run(self, body):

        # check that command is correct one
        if body["data"]["name"] == self.name:

            # run command
            print(f"Running followup command: {self.name}")
            interaction_id, interaction_token, payload = self.action(body)

            from dexobot.helper import send_discord_followup
            ok = send_discord_followup(interaction_id, interaction_token, payload)

            return ok

