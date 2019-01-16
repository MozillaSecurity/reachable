from django.conf.urls import url
from django.conf.urls import include
from rest_framework import routers

from . import views

router = routers.DefaultRouter()
router.register(r'queries', views.QueryViewSet, base_name='queries')
router.register(r'results', views.QueryResultViewSet, base_name='results')
router.register(r'mozsearchindexfiles', views.MozsearchIndexFileViewSet, base_name='mozsearchindexfiles')

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^queries/$', views.queries, name="queries"),
    url(r'^queries/api/create/$', views.QueryViewSet.as_view({'post': 'create'}),
        name="query_create_api"),
    url(r'^queries/api/', views.QueryViewSet.as_view({'get': 'list'}), name="query_list_api"),
    url(r'^queries/compute_api/$', views.query_compute_api, name="query_compute_api"),

    url(r'^mozsearchindex/api/', views.MozsearchIndexFileViewSet.as_view({'get': 'list'}),
        name="mozsearchindex_list_api"),

    url(r'^results/api/', views.QueryResultViewSet.as_view({'get': 'list'}), name="result_list_api"),
    url(r'^results/graph_api/$', views.query_result_graph_api, name="query_result_graph_api"),

    url(r'^rest/', include(router.urls)),
]
