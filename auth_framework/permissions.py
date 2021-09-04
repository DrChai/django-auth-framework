from oauth2_provider.contrib.rest_framework import TokenHasScope
from rest_framework import permissions


import logging

log = logging.getLogger('oauth2_provider')


class IsAuthenticatedAndActive(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_active


class IsAdminOrIsSelf(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user or request.user.is_staff or request.user.is_superuser


class IsSelfOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            return obj == request.user


class ScopesIsSelfOrReadOnly(TokenHasScope):

    def has_permission(self, request, view):
        token = request.auth

        if not token:
            return False

        if hasattr(token, 'scope'):  # OAuth 2
            required_scopes = self.get_scopes(request, view)
            log.debug("Required scopes to access resource: {0}".format(required_scopes))

            return token.is_valid(required_scopes)

        assert False, ('TokenHasScope requires either the'
                       '`oauth2_provider.rest_framework.OAuth2Authentication` authentication '
                       'class to be used.')

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return self.has_permission(request, view)
        else:
            return obj == request.user


# maybe only using for testing...
class IsAdminOrScopesSelfOrReadOnly(ScopesIsSelfOrReadOnly):

    def has_permission(self, request, view):
        token = request.auth

        if request.user and request.user.is_authenticated and request.user.is_superuser:
            return True
        elif not token:
            return False

        if hasattr(token, 'scope'):  # OAuth 2
            required_scopes = self.get_scopes(request, view)
            log.debug("Required scopes to access resource: {0}".format(required_scopes))

            return token.is_valid(required_scopes)

        assert False, ('TokenHasScope requires either the'
                       '`oauth2_provider.rest_framework.OAuth2Authentication` authentication '
                       'class to be used.')
