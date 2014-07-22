import argparse
import bcrypt
import re
import random
import base64
import binascii
import os
from shutil import rmtree, copy

from KerbalStuff.config import _cfg, _cfgi
from KerbalStuff.database import db, init_db
from KerbalStuff.objects import User, Mod, ModVersion, DownloadEvent, FollowEvent, ReferralEvent, Featured, Media, GameVersion
from KerbalStuff.email import send_confirmation
from werkzeug.utils import secure_filename
import zipfile

init_db()

def delete_user(args):
    username = args.username
    user = User.query.filter(User.username == username).first()
    if not user:
        print("User", username, "not found.")
        return False
    else:
        db.delete(user)
        db.commit()
        print("Successfully deleted user", username)
        return True

def create_user(args):
    username = args.username
    email = args.email
    password = args.password
    confirmation = args.confirmation
    public = args.public
    kwargs = dict()
    if not email:
        kwargs['emailError'] = 'Email is required.'
    else:
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            kwargs['emailError'] = 'Please specify a valid email address.'
        elif db.query(User).filter(User.email == email).first():
            kwargs['emailError'] = 'A user with this email already exists.'
    if not username:
        kwargs['usernameError'] = 'Username is required.'
    else:
        if not re.match(r"^[A-Za-z0-9_]+$", username):
            kwargs['usernameError'] = 'Please only use letters, numbers, and \
                underscores.'
        if len(username) < 3 or len(username) > 24:
            kwargs['usernameError'] = 'Usernames must be between 3 and 24 \
                characters.'
        if db.query(User).filter(User.username.ilike(username)).first():
            kwargs['usernameError'] = 'A user by this name already exists.'
    if not password:
        kwargs['passwordError'] = 'Password is required.'
    else:
        if len(password) < 5:
            kwargs['passwordError'] = 'Your password must be greater than 5 \
                characters.'
        if len(password) > 256:
            kwargs['passwordError'] = 'We admire your dedication to security, \
                but please use a shorter password.'
    if not kwargs == dict():
        if kwargs.get('emailError'):
            print('Email errors:\n', kwargs['emailError'])
        if kwargs.get('usernameError'):
            print('Username errors:\n', kwargs['usernameError'])
        if kwargs.get('passwordError'):
            print('Password errors:\n', kwargs['passwordError'])
        return False
    # All valid, let's make them an account
    user = User(username, email, password)
    if confirmation:
        user.confirmation = binascii.b2a_hex(os.urandom(20)).decode("utf-8")
    if public:
        user.public = True
    db.add(user)
    db.commit() # We do this manually so that we're sure everything's hunky 
    # dory before the email leaves
    if confirmation:
        send_confirmation(user)
    print("Successfully added user", username)
    return True

def delete_mod(args):
    mod = Mod.query.filter(Mod.id == args.mod_id).first()
    if not mod:
        print('Mod not found')
        return False
    db.delete(mod)
    for feature in Featured.query.filter(Featured.mod_id == mod.id).all():
        db.delete(feature)
    for media in Media.query.filter(Media.mod_id == mod.id).all():
        db.delete(media)
    for version in ModVersion.query.filter(ModVersion.mod_id == mod.id).all():
        db.delete(version)
    base_path = os.path.join(secure_filename(mod.user.username) + '_' + str(mod.user.id), secure_filename(mod.name))
    full_path = os.path.join(_cfg('storage'), base_path)
    db.commit()
    rmtree(full_path)
    print('Success')
    return True

def create_mod(args):
    user = User.query.filter_by(username=args.username).first()
    if not user.public:
        print('Only public users can create mods')
        return False
    name = args.name
    description = args.description
    short_description = args.short_description
    version = args.version
    ksp_version = args.ksp_version
    license = args.license
    publish = args.publish
    zipball = args.zipball
    # Validate
    if len(name) > 100 \
        or len(description) > 100000 \
        or len(donation_link) > 512 \
        or len(external_link) > 512 \
        or len(license) > 128 \
        or len(source_link) > 256:
        print('Something is too long')
        return False
    if not os.path.isfile(zipball):
        print('Mod file not found')
        return False
    mod = Mod()
    mod.user = user
    mod.name = name
    mod.description = description
    mod.short_description = short_description
    mod.license = license
    if publish:
        mod.published = True
    # Save zipball
    filename = secure_filename(name) + '-' + secure_filename(version) + '.zip'
    base_path = os.path.join(secure_filename(user.username) + '_' + str(user.id), secure_filename(name))
    full_path = os.path.join(_cfg('storage'), base_path)
    if not os.path.exists(full_path):
        os.makedirs(full_path)
    path = os.path.join(full_path, filename)
    if os.path.isfile(path):
        # We already have this version
        # We'll remove it because the only reason it could be here on creation is an error
        os.remove(path)
    shutil.copy(zipball, path)
    if not zipfile.is_zipfile(path):
        os.remove(path)
        print('Mod must be zip')
        return False
    version = ModVersion(secure_filename(version), ksp_version, os.path.join(base_path, filename))
    mod.versions.append(version)
    db.add(version)
    # Save database entry
    db.add(mod)
    db.commit()
    mod.default_version_id = version.id
    print('Successfully added mod', mod.name, 'under user', user.username)
    return True

def create_version(args):
    username = args.username
    email = args.email
    password = args.password
    confirmation = args.confirmation
    public = args.public

def delete_version(args):
    username = args.username
    email = args.email
    password = args.password
    confirmation = args.confirmation
    public = args.public

def main():
    parser = argparse.ArgumentParser(description='KerbalStuff admin tool.')
    subparsers = parser.add_subparsers(help='Choose a sub command')

    sub_delete_user = subparsers.add_parser('delete_user')
    sub_delete_user.add_argument('username')
    sub_delete_user.set_defaults(func=delete_user)

    sub_create_user = subparsers.add_parser('create_user')
    sub_create_user.add_argument('username')
    sub_create_user.add_argument('email')
    sub_create_user.add_argument('password')
    sub_create_user.add_argument('--send_confirmation', dest='confirmation',
        action='store_true')
    sub_create_user.add_argument('--make_public', dest='public',
        action='store_true')
    sub_create_user.set_defaults(func=create_user)

    sub_delete_mod = subparsers.add_parser('delete_mod')
    sub_delete_mod.add_argument('mod_id')
    sub_delete_mod.set_defaults(func=delete_mod)

    sub_create_user = subparsers.add_parser('create_user')
    sub_create_user.add_argument('username')
    sub_create_user.add_argument('email')
    sub_create_user.add_argument('password')
    sub_create_user.add_argument('--send_confirmation', dest='confirmation',
        action='store_true')
    sub_create_user.add_argument('--make_public', dest='public',
        action='store_true')
    sub_create_user.set_defaults(func=create_user)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()