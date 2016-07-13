
import bcrypt
import uuid

from sqlalchemy import create_engine, Sequence, inspect
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Table
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base

import config as cfg
import utils

from tornado.log import gen_log

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    email = Column(String(75), nullable=False, unique=True)
    password = Column(String(128), nullable=False)
    token = Column(String(128), nullable=True)
    tokendate = Column(Float, nullable=True)

    notes = relationship('Note', back_populates='user')
    tags = relationship('Tag', back_populates='user')

    def __repr__(self):
        return "User '{}', with token={}, token created {}".\
               format(self.email, self.token, self.tokendate)


note_tags = Table('note_tags', Base.metadata,
         Column('noteid', ForeignKey('notes.key'), primary_key=True),
         Column('tagid', ForeignKey('tags.id'), primary_key=True)
)


class Note(Base):
    __tablename__ = 'notes'
    key = Column(String(128), Sequence('id_seq'), primary_key=True)
    deleted = Column(Integer, nullable=False)
    create = Column(Float, nullable=False)
    modify = Column(Float, nullable=False)
    syncnum = Column(Integer, nullable=False)
    version = Column(Integer, nullable=False)
    minversion = Column(Integer, nullable=False)
    publishkey = Column(String(128))
    sharekey = Column(String(128))
    content = Column(String(100000), nullable=False) # TODO: what is max value?

    # system tags
    # TODO: more efficient as bit array?
    pinned = Column(Integer, nullable=False)
    unread = Column(Integer, nullable=False)
    markdown = Column(Integer, nullable=False)
    islist = Column(Integer, nullable=False)

    # the user the note belongs to
    userid = Column(Integer, ForeignKey('users.id'), nullable=False)

    user = relationship('User', back_populates='notes')

    versions = relationship('Version', back_populates='note')

    tags = relationship('Tag',
                        secondary=note_tags,
                        back_populates='notes')

    def dict(self):
        data = {}
        data['key'] = self.key
        data['content'] = self.content
        data['createdate'] = self.create
        data['modifydate'] = self.modify
        data['syncnum'] = self.syncnum
        data['deleted'] = self.deleted
        data['version'] = self.version
        data['minversion'] = self.minversion
        data['tags'] = [tag.name for tag in self.tags]

        if self.publishkey:
            data['publishkey'] = self.publishkey
        if self.sharekey:
            data['sharekey'] = self.sharekey

        systags = []
        if self.pinned == 1:
            systags.append('pinned')
        if self.markdown == 1:
            systags.append('markdown')
        if self.unread == 1:
            systags.append('unread')
        if self.islist == 1:
            systags.append('list')
        data['systemtags'] = systags
        return data

    def short_dict(self):
        d = self.dict()
        del d['content']
        return d

class Version(Base):
    __tablename__ = 'versions'

    key = Column(Integer, ForeignKey('notes.key'), primary_key=True)
    versiondate = Column(Float)
    content = Column(String(100000))
    version = Column(Integer, nullable=False, primary_key=True)

    note = relationship('Note', back_populates='versions')

    def dict(self):
        data = {}
        data['content'] = self.content
        data['versiondate'] = self.versiondate
        data['version'] = self.version
        return data

class Tag(Base):
    __tablename__ = 'tags'
    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    lower_name = Column(String(100), nullable=False, unique=True)
    index = Column(Integer, Sequence('id_seq'))
    userid = Column(Integer, ForeignKey('users.id'), nullable=False)

    user = relationship('User', back_populates='tags')
    notes = relationship('Note',
                             secondary=note_tags,
                             back_populates='tags')


    def __init__(self, userid, name, index=None):
        self.userid = userid
        self.name = name
        self.lower_name = name.lower()
        if index is not None:
            self.index = index

    def dict(self):
        data = {}
        data['name'] = self.name
        data['count'] = len(self.notes)
        return data


# NOTE: processing is split up between functions in the below class, and
# functions in the server. All functions here assume sanitized data, everything
# in the server code must treat all incoming data as untrusted and only send to
# db when fully sanitized 

class db():
    """db object to use from app.py in the request handlers"""
    def __init__(self, url):
        self.engine = create_engine(url, echo=False)
        self.metadata = Base.metadata
        self.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine)()

    def create_all(self):
        self.metadata.create_all(self.engine)

    def create_user(self, email, password):

        # hash the password
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        user = User(email=email, password=hashed)
        self.session.add(user)
        if self.commit():
            return user
        return None

    def authenticate(self, email, password):
        user = self.session.query(User).filter_by(email=email).first()
        if user and bcrypt.hashpw(password.encode(), user.password) == user.password:
            return user
        return None

    def authenticate_token(self, email, token):
        user = self.session.query(User).filter_by(email=email).first()
        if user and user.token and user.tokendate:
            if user.token == token and \
              (utils.now()-user.tokendate) <= cfg.token_max_age:
                return user
        return None

    def get_user(self, email):
        return self.session.query(User).filter_by(email=email).first()

    def _gen_token(self, user):
        user.token = str(uuid.uuid4())
        user.tokendate = utils.now()
        if self.commit():
            return user.token
        return None

    def get_token(self, user):
        if user.token and utils.now() - user.tokendate < cfg.token_max_age:
            return user.token
        else:
            return self._gen_token(user)
        
    def del_token(self, user):
        user.token = None
        user.tokendate = None
        if self.commit():
            return True
        return False

    def get_note(self, user, key, version=None):
        note = self.session.query(Note).filter_by(userid=user.id, key=key).one_or_none()
        if version is not None and version != note.version:
            note = self.session.query(Version).filter_by(key=key, version=version).one_or_none()
        return note.dict() if note else None

    def get_raw_note(self, user, key):
        return self.session.query(Note).filter_by(userid=user.id, key=key).first()

    def get_notes(self, user, since=None, tags=None):
        query = self.session.query(Note).filter_by(userid=user.id)
        if since:
            query = query.filter(Note.modify > since)
        if tags:
            for tagname in tags:
                query = query.filter(Note.tags.any(lower_name=tagname))

        notes = query.all()

        return [n.dict() for n in notes]

    def _gen_unique_key(self):
        return str(uuid.uuid4()) + str(int(utils.now()))

    # makes a new note object - used by the server part in creating notes
    def new_note(self, user):
        now = utils.now()

        note = Note()

        note.user = user

        note.key = self._gen_unique_key()
        note.deleted = 0
        note.modify = now
        note.create = now
        note.syncnum = 1
        note.version = 1
        note.minversion = 1
        note.sharekey = None
        note.systemtags = []
        note.tags = []
        note.content = ''
        
        return note

    # adds or updates a note to the database.
    def add_note(self, note, tags, systemtags):
        user = note.user

        if systemtags is not None:
            note.pinned = 1 if 'pinned' in systemtags else 0
            note.unread = 1 if 'unread' in systemtags else 0
            note.markdown = 1 if 'markdown' in systemtags else 0
            note.islist = 1 if 'list' in systemtags else 0

        old_tags = [t for t in note.tags]
        if tags is not None:
            note.tags = []
            for tagname in tags:
                t = self.session.query(Tag).filter_by(lower_name=tagname.lower(), userid=user.id).one_or_none()
                if not t:
                    t = Tag(user.id, tagname)
                note.tags.append(t)

        # delete any tags no longer in use
        # TODO: check this works
        for t in old_tags:
            count = self.session.query(Note).filter(Note.tags.any(id=t.id)).count()
            if count == 0:
                self.session.delete(t)

        # check if the note is in the session yet - won't be if this is a new
        # note
        if inspect(note).transient:
            self.session.add(note)

        if not self.commit():
            return note.dict()
        return None

    def delete_note(self, user, note):

        old_tags = [t for t in note.tags]
        self.session.delete(note)

        # delete any tags no longer in use
        for t in old_tags:
            count = self.session.query(Note).filter(Note.tags.any(id=t.id)).count()
            if count == 0:
                self.session.delete(t)

        if self.commit():
            return True
        return False

    def save_version(self, note):
        v = Version()
        v.key = note.key
        v.versiondate = note.modifydate
        v.content = note.content
        v.version = note.version
        self.session.add(v)

    def _drop_old_versions(self, note, minversion):
        self.session.query(Version).filter(Version.version < minversion).delete()

    def notes_index(self, user, length, since, mark):
        notes = self.session.query(Note).filter(Note.userid==user.id).filter(Note.modify > since).order_by(Note.modify).all()

        data = {}
        data['notes'] = [n.short_dict() for n in notes[mark:mark+length]]
        data['count'] = len(data['notes'])

        # add new mark if needed
        total = len(notes)
        if (total - mark - length) > 0:
            data['mark'] = mark+length

        return data

    def tags_index(self, user, length, mark):
        tags = self.session.query(Note).filter(Note.userid==user.id).order_by(Tag.index).all()

        data = {}
        data['tags'] = [n.short_dict() for n in tags[mark:mark+length]]
        data['count'] = len(data['tags'])

        # add new mark if needed
        total = len(tags)
        if (total - mark - length) > 0:
            data['mark'] = mark+length

        return data

    def get_tags(self, user):
        tags = self.session.query(Tag).filter_by(userid=user.id).all()
        return [t.dict() for t in tags] if tags else []

    def get_tag(self, user, tagname):
        tag = self.session.query(Tag).filter_by(userid=user.id, name=tagname).one_or_none()
        if tag:
            return tag.dict()
        return None

    def del_tag(self, user, tagname):
        tag = self.session.query(Tag).filter_by(userid=user.id, name=tagname).one_or_none()
        if tag:
            # update the modify date on all related notes
            now = utils.now()
            for bm in tag.notes:
                bm.modify = now

            self.session.delete(tag)
            if self.commit():
                return (200, True)
            else:
                return (500, False)
        return (404, False)

    def rename_tag(self, user, old, new):
        tag = self.session.query(Tag).filter_by(userid=user.id, name=old).one_or_none()
        check_new = self.session.query(Tag).filter_by(userid=user.id, name=new).one_or_none()
        # make sure old name exists
        if not tag:
            return (404, None)

        now = utils.now()
        # if tag with new name already exists, merge
        if check_new:
            for bm in tag.notes:
                bm.tags.append(check_new)
                bm.modify = now
            self.session.delete(tag)
            if self.commit():
                return (200, check_new.dict())

        # otherwise, just update the name
        else:
            tag.name = new
            # update the modify date on all related notes
            for bm in tag.notes:
                bm.modify = now
            if self.commit():
                return (200, tag.dict())

        return (500, None)

    def commit(self):
        # TODO: check this and make sure will work
        try:
            self.session.commit()
            return True
        except:
            self.session.rollback()
            return False

