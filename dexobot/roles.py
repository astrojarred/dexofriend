from dexobot import metadata

DEXOWORLDS_POLICY_ID = "862cd06c4504de6114a29e0b863751ee84ad455493d43aeeb727d896"
WORLDS_METADATA_PATH = "./data/worlds.json"
STARS_METADATA_PATH = "./data/stars.json"

class SpecialRoles:
    @staticmethod
    def starlord(user_assets):

        dexos = user_assets.get(DEXOWORLDS_POLICY_ID)

        if not dexos:
            return False

        world_ids = [int(i.strip("DexoWorld")) for i in list(dexos.keys())]

        info = metadata.get_world(world_ids, WORLDS_METADATA_PATH)

        star_ids = sorted(list(set([v["host_star_id"] for k, v in info.items()])))

        stars_metadata = metadata.get_star(star_ids, STARS_METADATA_PATH)

        complete_starsystems = []

        for k, v in stars_metadata.items():
            if all(world in world_ids for world in v["planet_ids"]):
                complete_starsystems.append(k)

        if complete_starsystems:
            starlord = True
        else:
            starlord = False

        return starlord

SPECIAL_CODES = {
    "!!dexo_starlords": {
        "function": SpecialRoles.starlord,
        "policies": [DEXOWORLDS_POLICY_ID],
    },
}

