import json


def get_world(world_id, worlds_metadata_path):

    with open(worlds_metadata_path, "r") as f:
        worlds = json.load(f)

    if isinstance(world_id, list):
        metadata = {i: worlds[str(i)] for i in world_id}
    else:
        metadata = {world_id: worlds[str(world_id)]}

    return metadata


def get_star(star_id, stars_metadata_path):

    with open(stars_metadata_path, "r") as f:
        stars = json.load(f)

    if isinstance(star_id, list):
        metadata = {i: stars[str(i)] for i in star_id}
    else:
        metadata = {star_id: stars[str(star_id)]}

    return metadata


def get_star_extras(star_id, stars_extra_metadata_path):

    with open(stars_extra_metadata_path, "r") as f:
        stars = json.load(f)

    extra_metadata = {star_id: stars[str(star_id)]}

    return extra_metadata

def get_all_worlds(worlds_metadata_path):

    with open(worlds_metadata_path, "r") as f:
        worlds = json.load(f)

    return worlds


def get_all_stars(stars_metadata_path):

    with open(stars_metadata_path, "r") as f:
        stars = json.load(f)

    return stars
