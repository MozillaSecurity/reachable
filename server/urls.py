from django.conf.urls import include, url
from django.contrib import admin
from django.contrib.auth.views import logout
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

from .views import index, login

admin.autodiscover()

urlpatterns = [
    # url(r'^oidc/', include('mozilla_django_oidc.urls')),  # uncomment this for mozilla_django_oidc
    url(r'^$', index, name='index'),
    # url(r'^admin/', include(admin.site.urls)),
    url(r'^login/$', login, name="login"),
    url(r'^logout/$', logout, name="logout"),
    url(r'^reachable/', include('reachable.urls', namespace="reachable", app_name='reachable')),
]

urlpatterns += staticfiles_urlpatterns()
