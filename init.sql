
-- init the sqlite database

create table if not exists users 
(
  id integer not null,
  email  text not null,
  hashed text not null,
  token text,
  tokendate numeric, -- seconds since epoch
  unique (email),
  primary key (id)
);

create table if not exists notes 
(
  id integer not null,
  key text not null,
  deleted integer,  -- should be 0 or 1
  modifydate numeric, -- seconds since epoch
  createdate numeric, -- seconds since epoch
  syncnum integer,
  minversion integer,
  publishkey text,
  content text,

  primary key (id),
  unique (key)
)




