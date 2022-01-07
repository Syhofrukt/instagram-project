from flask import Blueprint, jsonify
from crud import posts_crud
from core.errors import ConflictError
from core.db import get_connection
from blueprints import deps
from models.posts import BaseCreatePostModel, BaseDeletePostModel

posts_blueprint = Blueprint("posts_blueprint", __name__, url_prefix="/posts")


@posts_blueprint.route("", methods=["POST"])
def create_post():
    current_user = deps.get_current_user()
    post_data = deps.get_input(BaseCreatePostModel)

    with get_connection() as conn:
        posts_crud.create(conn, post_data, current_user)

    return jsonify({"info": "OK"}), 201


@posts_blueprint.route("", methods=["DELETE"])
def delete_post():
    current_user = deps.get_current_user()
    delete_data = deps.get_input(BaseDeletePostModel)

    with get_connection() as conn:
        lst = []
        for i in range(len(posts_crud.get_by_creator(conn, current_user))):
            lst.append(str(posts_crud.get_by_creator(conn, current_user)[i].id))
        if delete_data.id not in lst:
            raise ConflictError("No post with such id was found")
        posts_crud.delete(conn, delete_data)

    return jsonify({"info": "OK"}), 201


@posts_blueprint.route("")
def get_posts_feed():
    current_user = deps.get_current_user()

    with get_connection() as conn:
        posts = posts_crud.get_by_subsciber(conn, current_user)

    return jsonify([post.dict() for post in posts])
