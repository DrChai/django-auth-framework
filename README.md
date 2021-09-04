
[![Contributors][contributors-shield]][contributors-url]

[comment]: <> ([![Forks][forks-shield]][forks-url])

[comment]: <> ([![Stargazers][stars-shield]][stars-url])
[![Issues][issues-shield]][issues-url]



<br />
<p align="center">

  <h3 align="center">Django Auth Framework</h3>

  <p align="center">
    An open source, one-stop authentication framework for Django and ready for production.
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
        <li><a href="#features">Features</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installation">Installation</a></li>
        <li><a href="#configurations">Configurations</a></li>
      </ul>
    </li>
    <li><a href="#api-endpoints-and-examples">API Endpoints and Examples</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project
Django Auth Framework is an open source, one-stop framework for Django applications providing the most essential APIs for 
authentication and authorization. APIs also cover Oauth2 protocol, social login and user management with options allows 
to easily customize and override for working on most scenarios. It supports multiple
authentication ways to make your auth server scalable from a monolithic server using Token/Session authentication to
service mesh such like [Istio](https://istio.io/latest/docs/tasks/security/authorization/authz-jwt/) on Kubernetes Cluster with JWT authentication.

This framework was originally developed by me to help
Django projects in our company fast setup. Now, it has scaled our service over a million users. I am 
happy to open soucre this project, hope it is helpful in your projects or startups

### Built With

* [Django OAuth Toolkit](https://github.com/jazzband/django-oauth-toolkit)
* [Django REST framework](https://github.com/encode/django-rest-framework)

### Features
* Production-ready, optimized by reducing unnecessary queries write to db during authentication and authorization.
* Extends [Django OAuth Toolkit's](https://github.com/jazzband/django-oauth-toolkit) default `Oauth2Validator` to allow
  authorization with multiple types of credentials like email, phone number.
* Pure RESTFUL API endpoints implemented with [Django REST framework](https://github.com/encode/django-rest-framework),
  this framework doesn't use any traditional Django components(eg: forms, html).
* Supports the most popular social login(Google,Apple and Facebook) followed by up to date guidelines, users at frontend
  can be authorized by either id_token, code or access_token.  
* **NO FULL DOCUMENTATION** atm.

<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.

### Installation

  ```sh
  pip install django-auth-framework
  ```

### Configurations
1. Edit `settings.py` file:
   
   ```python
    #in your my_auth/models.py
     # from auth_framework.models import AbstractUser
     # class MyUser(AbstractUser):
     #     custom_fields ...
    AUTH_USER_MODEL = 'my_auth.MyUser'
   ```
   or just try with
   ```python
    AUTH_USER_MODEL = 'auth_framework.User'
   ```
   add required apps and configuration for rest_framework:
   ```python
   # ...
   REQUIRED_APPS = [
        'rest_framework',
        'oauth2_provider',
        'auth_framework',
   ]
   LOCAL_APPS = [
        'my_auth'
   ]
   INSTALLED_APPS += REQUIRED_APPS
   INSTALLED_APPS += LOCAL_APPS
    # ...
    REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
        'rest_framework.authentication.SessionAuthentication',

    ),
    }
    ```
   if you need other unique fields: `email` or `phone_number` not just`username`as credentials:
   ```python
    AUTHENTICATION_BACKENDS = [
        "auth_framework.backends.auth_backends.AuthenticationBackend",
    ]
    
    OAUTH2_PROVIDER = {
        "OIDC_ENABLED": True,
        "OIDC_RSA_PRIVATE_KEY": os.environ.get('OIDC_RSA_PRIVATE_KEY'),
        'SCOPES': {
            "openid": "OpenID Connect scope",
            'read': 'Read scope',
            'write': 'Write scope',
        },
        'OAUTH2_VALIDATOR_CLASS': 'auth_framework.oauth.oauth2_validators.OauthValidator',
        'OAUTH2_BACKEND_CLASS': 'auth_framework.oauth.oauth2_backends.OAuthLibCore',
    }
    ```
2. Edit the `urls.py`:
   ```python
   from django.contrib import admin
   from django.urls import path, include
   
   urlpatterns = [
      path('admin/', admin.site.urls),
      path('account/', include('auth_framework.urls'))
   ]
    
    ```
3. Sync Database and createsuperuser:
    ```sh
   python manage.py migrate
   python manage.py createsuperuser
   ```
4. Login to the admin page http://localhost:8000/admin/oauth2_provider/application/add/
   and add a default `Application`. if it's only open to your first party apps, then just choose `Resource owner password-based`
   as the grant type (No one likes to login with password but still having a redirect web page on a native app)

5. [Optional] Configure of Social Adapters: in most scenarios, you only need to create one client id/secret for each social
   provider. For security and performance, it will look up those environment variables during making Oauth request calls
   instead of creating many key pairs to the database:
    ```sh
   GOOGLE_CLIENT_ID=*********.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=**********
   FACEBOOK_CLIENT_ID=**********
   FACEBOOK_CLIENT_SECRET=**************
   APPLE_CLIENT_ID=com.team.project
   APPLE_CLIENT_SECRET=**************
   ```
   If this is not your thing, consider to use [allauth-django](https://github.com/pennersr/django-allauth)

<!-- API Endpoints and Examples -->
## API Endpoints and Examples
 [Postman](https://documenter.getpostman.com/view/1635081/U16ewUEQ)


<!-- CONTRIBUTING -->
## Contributing

If you have improvements to Django Auth Framework, just send a pull request:
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Or leave a comment in our [Issues](issues-url)


<!-- LICENSE -->
## License

Distributed under the BSD License. See `LICENSE` for more information.





<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/DrChai/django-auth-framework?style=for-the-badge
[contributors-url]: https://github.com/DrChai/django-auth-framework/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/DrChai/django-auth-framework?style=for-the-badge
[forks-url]: https://github.com/DrChai/django-auth-framework/network/members
[stars-shield]: https://img.shields.io/github/stars/DrChai/django-auth-framework?style=for-the-badge
[stars-url]: https://github.com/DrChai/django-auth-framework/stargazers
[issues-shield]: https://img.shields.io/github/issues/DrChai/django-auth-framework?style=for-the-badge
[issues-url]: https://github.com/DrChai/django-auth-framework/issues
[license-shield]: https://img.shields.io/github/license/DrChai/django-auth-framework?style=for-the-badge
[license-url]: https://github.com/DrChai/django-auth-framework/blob/master/LICENSE.txt
