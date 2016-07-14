
# the database to connect to, in format that can be read by
# sqlalchemy.create_engine
# see http://docs.sqlalchemy.org/en/latest/core/engines.html#sqlalchemy.create_engine
database_url = 'sqlite:///db.sqlite3'

# maximum token age before forced to get a new token (in seconds)
# - default = 24 hours
token_max_age = 60 * 60 * 24

# set which origins are allowed to access with CORS
cors_origin = "*"

# Tornado options
listen_port = 8888
listen_host = "127.0.0.1"
debug = True

# note options
max_versions = 20

tag_max_len = 50
