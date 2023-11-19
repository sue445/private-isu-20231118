ALTER TABLE users ADD INDEX index_authority_del_flg_created_at (authority, del_flg, created_at);

ALTER TABLE comments ADD INDEX index_post_id (post_id);
ALTER TABLE comments ADD INDEX index_user_id (user_id);

ALTER TABLE posts ADD INDEX index_user_id (user_id);
ALTER TABLE posts ADD INDEX index_created_at (created_at);
