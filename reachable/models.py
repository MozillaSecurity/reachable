from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.db import models
from django.db.models.signals import post_save
from django.dispatch.dispatcher import receiver
from django.utils import timezone
import codecs
import json
import logging

from django.contrib.auth.models import User as DjangoUser, Permission
from django.contrib.contenttypes.models import ContentType

QUERY_TYPE_CODE = {
    0: "dead-code",
    1: "reachable-code",
}
QUERY_TYPE = dict((val, key) for key, val in QUERY_TYPE_CODE.items())


class MozsearchIndexFile(models.Model):
    created = models.DateTimeField(default=timezone.now)
    file = models.FileField(storage=FileSystemStorage(location=getattr(settings, 'DATA_STORAGE', None)),
                            max_length=255,
                            upload_to="index")
    os = models.CharField(max_length=255, blank=False)
    revision = models.CharField(max_length=255, blank=False)


class Query(models.Model):
    created = models.DateTimeField(default=timezone.now)
    description = models.CharField(max_length=1023, blank=True)
    target_path = models.CharField(max_length=1023, blank=True)
    source_path = models.CharField(max_length=1023, blank=True)
    type = models.IntegerField()


class QueryResult(models.Model):
    created = models.DateTimeField(default=timezone.now)
    query = models.ForeignKey(Query)
    progress = models.CharField(max_length=4095, blank=True)
    indexfiles = models.ManyToManyField(MozsearchIndexFile)
    file = models.FileField(storage=FileSystemStorage(location=getattr(settings, 'DATA_STORAGE', None)),
                            max_length=255,
                            upload_to="result", null=True)

    def __init__(self, *args, **kwargs):
        # This variable can hold the deserialized contents of the result blob
        self.result = None
        super(QueryResult, self).__init__(*args, **kwargs)

    def loadResult(self):
        self.file.open(mode='rb')
        self.result = json.load(codecs.getreader('utf-8')(self.file))
        self.file.close()


class User(models.Model):
    class Meta:
        permissions = (
            ("view_reachable", "Can see Reachable app"),
        )

    user = models.OneToOneField(DjangoUser)

    @staticmethod
    def get_or_create_restricted(request_user):
        (user, created) = User.objects.get_or_create(user=request_user)
        return (user, created)


@receiver(post_save, sender=DjangoUser)
def add_default_perms(sender, instance, created, **kwargs):
    if created:
        log = logging.getLogger('reachable')
        for perm in getattr(settings, 'DEFAULT_PERMISSIONS', []):
            model, perm = perm.split(':', 1)
            module, model = model.rsplit('.', 1)
            module = __import__(module, globals(), locals(), [model], 0)  # from module import model
            content_type = ContentType.objects.get_for_model(getattr(module, model))
            perm = Permission.objects.get(content_type=content_type, codename=perm)
            instance.user_permissions.add(perm)
            log.info('user %s added permission %s:%s', instance.username, model, perm)
