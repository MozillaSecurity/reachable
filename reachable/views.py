from django.core.exceptions import SuspiciousOperation
from django.http import Http404
from django.http.response import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
import json
from rest_framework import mixins, viewsets, filters
from rest_framework.authentication import TokenAuthentication, \
    SessionAuthentication

from server.views import JsonQueryFilterBackend, SimpleQueryFilterBackend

from .models import Query, QueryResult, MozsearchIndexFile
from .serializers import QuerySerializer, QueryResultSerializer, MozsearchIndexFileSerializer
from .tasks import perform_analysis


def index(request):
    return redirect('reachable:queries')


def queries(request):
    return render(request, 'queries/index.html', {})


def query_result_graph_api(request):
    queryresultid = request.GET.get('qrid')
    result = get_object_or_404(QueryResult, pk=queryresultid)

    if not result.file:
        return HttpResponse(
            content=json.dumps({
                "message": "The requested query result is currently being computed.",
                "progress": result.progress,
            }),
            content_type='application/json',
            status=204
        )

    result.loadResult()

    # Compute d3 graph data here
    graph = {"nodes": [], "links": []}

    nodemap = {}
    cnodeid = 1

    for node in result.result["graph"]["nodes"]:
        nodemap[node] = cnodeid
        graph["nodes"].append({"name": node, "label": node, "id": cnodeid})
        cnodeid += 1

    for edge in result.result["graph"]["edges"]:
        sid = nodemap[edge[0]]
        tid = nodemap[edge[1]]
        type = ""

        if len(edge) > 2:
            type = " ".join(edge[2:])

        graph["links"].append({"source": sid, "target": tid, "type": type})

    data = {"result": result.result, "progress": result.progress, "d3_graph": graph}
    return HttpResponse(json.dumps(data), content_type='application/json')


# @csrf_exempt
def query_compute_api(request):
    if request.method != 'POST':
            return HttpResponse(
                content=json.dumps({"error": "This API only supports POST."}),
                content_type='application/json',
                status=400
            )

    # if not request.is_ajax():
    #     raise SuspiciousOperation

    data = json.loads(request.body)

    for k in ["queryid", "mozindexid"]:
        if k not in data:
            raise SuspiciousOperation

    query = get_object_or_404(Query, pk=data["queryid"])
    mozindex = get_object_or_404(MozsearchIndexFile, pk=data["mozindexid"])

    result = QueryResult()
    result.query = query
    result.save()

    result.indexfiles.add(mozindex)
    result.save()

    perform_analysis.delay(result.pk)

    return HttpResponse(content=json.dumps({"newid": result.pk}), content_type='application/json')


class QueryResultViewSet(mixins.ListModelMixin,
                         mixins.RetrieveModelMixin,
                         viewsets.GenericViewSet):
    """
    API endpoint that allows viewing query results
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    queryset = QueryResult.objects.all()
    serializer_class = QueryResultSerializer
    paginate_by_param = 'limit'
    filter_backends = [
        JsonQueryFilterBackend,
        SimpleQueryFilterBackend
    ]


class QueryViewSet(mixins.CreateModelMixin,
                   mixins.UpdateModelMixin,
                   mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   viewsets.GenericViewSet):
    """
    API endpoint that allows adding/updating/viewing Report Configurations
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    queryset = Query.objects.all()
    serializer_class = QuerySerializer
    paginate_by_param = 'limit'
    filter_backends = [
        JsonQueryFilterBackend,
        SimpleQueryFilterBackend
    ]


class MozsearchIndexFileViewSet(mixins.ListModelMixin,
                                mixins.RetrieveModelMixin,
                                viewsets.GenericViewSet):
    """
    API endpoint that allows viewing query results
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    queryset = MozsearchIndexFile.objects.all()
    serializer_class = MozsearchIndexFileSerializer
    paginate_by_param = 'limit'
    filter_backends = [
        JsonQueryFilterBackend,
        SimpleQueryFilterBackend
    ]
