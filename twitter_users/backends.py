
from django.contrib.auth.models import User

from twitter_users.models import TwitterInfo
from twitter_users import settings

class TwitterBackend(object):
    def authenticate(self, twitter_id=None, username=None, token=None, secret=None):
        # find or create the user
        try:
            info = TwitterInfo.objects.get(id=twitter_id)
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
            email    = "%s@twitter.com" % username
            user     = User.objects.create_user(settings.USERS_FORMAT % username, email)
            user.save()
            info = TwitterInfo(user=user, name=username, id=twitter_id, token=token, secret=secret)
            info.save()
        return user
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
