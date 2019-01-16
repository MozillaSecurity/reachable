from rest_framework import serializers
from rest_framework.exceptions import APIException

from .models import Query, QueryResult, MozsearchIndexFile


class InvalidArgumentException(APIException):
    status_code = 400


class QueryResultSerializer(serializers.ModelSerializer):
    description = serializers.CharField(source='query.description', max_length=1023)
    source_path = serializers.CharField(source='query.source_path', max_length=1023)
    target_path = serializers.CharField(source='query.target_path', max_length=1023)
    indexfiles = serializers.CharField(max_length=1023, write_only=True)

    class Meta:
        model = QueryResult
        fields = (
            'source_path', 'target_path', 'description', 'indexfiles', 'id', 'created'
        )

    def to_representation(self, obj):
        serialized = super(QueryResultSerializer, self).to_representation(obj)
        if obj is not None:
            serialized["indexfiles"] = ",".join(["%s on %s" % (x.revision, x.os) for x in obj.indexfiles.all()])

        return serialized


class MozsearchIndexFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = MozsearchIndexFile
        fields = ('created', 'os', 'revision', 'id')


class QuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = Query
        fields = (
            'description', 'source_path', 'target_path', 'type', 'id', 'created'
        )
        read_only_fields = ('id', 'created')
