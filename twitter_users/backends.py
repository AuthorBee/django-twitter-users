
from django.contrib.auth.models import User

from twitter_users.models import TwitterInfo
from twitter_users import settings
import logging

import sys
import traceback

logger = logging.getLogger("twitter-users.backend")

class TwitterBackend(object):
    def authenticate(self, twitter_id=None, username=None, token=None, secret=None):
        logger.debug("Authenticating with: %s, %s, %s, %s" % (twitter_id, username, token, secret))
        # find or create the user
        try:
            info = TwitterInfo.objects.get(id=twitter_id)
            logger.debug("Found twitter user: %s" % info.name)
            # make sure the screen name is current
            _dirty = False
            if info.name != username:
                info.name = username
                _dirty = True
                
            #Sometimes the credentials change - ie, are revoked and the user reauthorizes, the app is updated, etc... 
            #We need to repersist if they change
            if info.token != token:
                info.token = token
                _dirty = True
            if info.secret != secret:
                info.secret = secret
                _dirty = True
            
            if _dirty:    
                info.save()
            user = info.user
        except TwitterInfo.DoesNotExist:
            logger.debug("User not found: %s" % username)
            email    = "%s@twitter.com" % username
            try:
                logger.debug("Creating user: %s with email: %s " % (username, email))
                user     = User.objects.create_user(settings.USERS_FORMAT % username, email)
                user.save()
                logger.debug("Saving twitter credentials: %s with twitter id: %s " % (username, twitter_id))
                info = TwitterInfo(user=user, name=username, id=twitter_id, token=token, secret=secret)
                info.save()
            except:
                (e, v, tb) = sys.exc_info()
                logger.warn(e)
                logger.warn(v)
                traceback.print_tb(tb)
        return user
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
