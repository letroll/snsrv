
import bcrypt
import uuid

from sqlalchemy import create_engine, Sequence
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
    index = Column(Integer, nullable=False)
    version = Column(Integer, nullable=False)
    userid = Column(Integer, ForeignKey('users.id'), nullable=False)

    user = relationship('User', back_populates='tags')
    notes = relationship('Note',
                             secondary=note_tags,
                             back_populates='tags')


    def __init__(self, userid, name, index=None):
        self.userid = userid
        self.name = name
        self.lower_name = name.lower()
        self.version = 1
        self.index = index if index is not None else 1

    def dict(self):
        data = {}
        data['name'] = self.name
        data['count'] = len(self.notes)
        data['index'] = self.index
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

    def get_note_object(self, user, key):
        return self.session.query(Note).filter_by(userid=user.id, key=key).one_or_none()

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
        # WARNING: don't call this part way through initializing a note
        # (calling session.query flushes)
        # unlikely, but might as well be sure
        # key = str(uuid.uuid4())
        # return key
        while True:
            key = str(uuid.uuid4())
            if not self.session.query(Note).filter_by(key=key).one_or_none():
                return key

    # makes a new note object - used by the server part in creating notes
    def new_note(self, user):
        now = utils.now()

        key = self._gen_unique_key()

        note = Note()

        note.user = user

        note.key = key
        note.deleted = 0
        note.modify = now
        note.create = now
        note.syncnum = 1
        note.version = 1
        note.minversion = 1
        note.sharekey = None
        note.tags = []
        note.content = ''
        note.pinned = 0
        note.unread = 0
        note.markdown = 0
        note.islist = 0

        return note

    def create_note(self, user, data):
        note = self.new_note(user)

        content = data.get('content')
        if content is None:
            return None
        note.content = content

        deleted = data.get('deleted')
        if deleted is not None:
            note.deleted = deleted
        modify = data.get('modify')
        if modify is not None:
            note.modify = modify
        create = data.get('create')
        if create is not None:
            note.create = create

        systemtags = data.get('systemtags')
        if systemtags is not None:
            note.pinned = 1 if 'pinned' in systemtags else 0
            note.unread = 1 if 'unread' in systemtags else 0
            note.markdown = 1 if 'markdown' in systemtags else 0
            note.islist = 1 if 'list' in systemtags else 0

        tags = data.get('tags')
        if tags is not None:
            note.tags = []
            for tagname in data.get('tags'):
                t = self.session.query(Tag).filter_by(lower_name=tagname.lower(), userid=user.id).one_or_none()
                if not t:
                    t = Tag(user.id, tagname)
                note.tags.append(t)

        self.session.add(note)

        if self.commit():
            return note.dict()
        return None

    # adds or updates a note to the database.
    def update_note(self, user, key, data):
        note = self.session.query(Note).filter_by(userid=user.id, key=key).one()

        content = data.get('content', None)
        if content is not None and content != note.content:
            # TODO: how to handle versions this way?
            # version vs modifydate
            version = data.get('version', None)
            if version is not None:
                if version <= note.version:
                    return None # older version of the note
            self._save_version(note)
            note.version += 1
            minversion = max(0, note.version - cfg.max_versions)
            if minversion > note.minversion:
                self._drop_old_versions(note, minversion)
            note.minversion = minversion
            note.content = content

        deleted = data.get('deleted')
        if deleted is not None:
            note.deleted = deleted
        modify = data.get('modify')
        if modify is not None:
            note.modify = modify
        create = data.get('create')
        if create is not None:
            note.create = create

        note.syncnum += 1

        systemtags = data.get('systemtags', None)
        if systemtags is not None:
            note.pinned = 1 if 'pinned' in systemtags else 0
            note.unread = 1 if 'unread' in systemtags else 0
            note.markdown = 1 if 'markdown' in systemtags else 0
            note.islist = 1 if 'list' in systemtags else 0

        old_tags = []
        # TODO: trigger markdown systemtag if markdown tag in tags
        tags = data.get('tags', None)
        if tags is not None:
            old_tags = [t for t in note.tags]
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

        if self.commit():
            return note.dict()
        return None

    def delete_note(self, user, note):

        old_tags = [t for t in note.tags]
        self.session.delete(note)

        # delete any tags no longer in use
        # TODO: is this wanted behaviour?
        for t in old_tags:
            count = self.session.query(Note).filter(Note.tags.any(id=t.id)).count()
            if count == 0:
                self.session.delete(t)

        if self.commit():
            return True
        return False

    def _save_version(self, note):
        v = Version()
        v.key = note.key
        v.versiondate = note.modify
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
        tags = self.session.query(Tag).filter(Tag.userid==user.id).order_by(Tag.index).all()

        data = {}
        data['tags'] = [t.dict() for t in tags[mark:mark+length]]
        data['count'] = len(data['tags'])
        # TODO: simplenote api doc shows 'time' property, but no
        # explanation

        # TODO: handle tag sharing ('share' property with email
        # addresses, auto-setup shared tag if tagname is email address)

        # add new mark if needed
        total = len(tags)
        if (total - mark - length) > 0:
            data['mark'] = mark+length

        return data

    def get_tags(self, user):
        tags = self.session.query(Tag).filter_by(userid=user.id).all()
        return [t.dict() for t in tags] if tags else []

    def get_tag(self, user, tagname):
        tag = self.session.query(Tag).filter_by(userid=user.id, lower_name=tagname.lower()).one_or_none()
        if tag:
            return tag.dict()
        return None

    def get_tag_object(self, user, tagname):
        tag = self.session.query(Tag).filter_by(userid=user.id, lower_name=tagname.lower()).one_or_none()
        if tag:
            return tag
        return None

    def del_tag(self, user, tag):

        # update the modify date on all related notes
        now = utils.now()
        for note in tag.notes:
            note.modify = now
            note.syncnum += 1

        # delete the tag
        self.session.delete(tag)
        if self.commit():
            return True
        return False

    def create_tag(self, user, name, index, version):
        # TODO: should handle version?
        lowername = name.lower()
        tag = self.session.query(Tag).filter_by(userid=user.id, lower_name=lowername).one_or_none()
        if tag:
            tag.index = index
            tag.version += 1
        else:
            tag = Tag(user.id, name, index)
            self.session.add(tag)
        if self.commit():
            return tag.dict()
        return None

    def update_tag(self, user, tag, newname, index, version):

        if newname is not None:
            lower_newname = newname.lower()
            now = utils.now()
            ret = None

            # see if already tag with name
            # if tag with new name already exists, merge
            check_new = self.session.query(Tag).filter_by(userid=user.id, lower_name=lower_newname).one_or_none()
            if check_new:
                for note in tag.notes:
                    note.tags.append(check_new)
                    note.modify = now
                    note.syncnum += 1
                self.session.delete(tag)
                if index is not None:
                    check_new.index = index
                # TODO: how does versioning work with tags?
                check_new.version += 1
                check_new.name = newname  # since newname could be different case
                ret = check_new

            # otherwise, update the current tag
            else:
                tag.name = newname
                tag.lower_name = lower_newname
                tag.version += 1  # or = version given?
                if index is not None:
                    tag.index = index
                ret = tag
                # update the modify time for each note
                for note in tag.notes:
                    note.modify = now
                    note.syncnum += 1
        else:
            if index is not None:
                tag.index = index
                tag.version += 1
            ret = tag

        if self.commit():
            return ret.dict()
        return None

    def commit(self):
        # TODO: need to catch errors whenever flush called (maybe turn off
        # autoflush?)
        try:
            self.session.commit()
            return True
        except Exception as e:
            gen_log.warn('error committing session: {}'.format(str(e)))
            self.session.rollback()
            return False

