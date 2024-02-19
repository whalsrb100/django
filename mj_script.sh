##############################################
# for root
##############################################

remove_user_afterwork="false"

workDir=$(pwd)
Username=django
Password='growin'
SuperUser=root
SuperPassword=${Password}
recreate_user="true"
myVENV="${Username}"
appDir=apps
baseDir="/home"
myProj="main"
myApps=(
    "home"
    "account"
    "mj"
)
homeApp=${myApps[0]}
loginApp=${myApps[1]}
mjApp=${myApps[2]}
django_version=5.0.2

if [ $(id -u) -eq 0 ];then
    if [ "${recreate_user}" == "true" ];then
        id ${Username} &> /dev/null
        if [ $? -eq 0 ];then
            userdel -rf ${Username} &> /dev/null
        fi
    fi
    id ${Username} &> /dev/null
    if [ $? -ne 0 ];then
        useradd -G wheel -M -s /bin/bash ${Username}
        echo "${Password}" | passwd --stdin ${Username} &> /dev/null
    fi
    cd ${baseDir}/
    if [ ! -d ${myVENV} ];then
        python3 -m venv ${myVENV}
        cd /etc/skel
        cp -apr $(ls -A) ${baseDir}/${myVENV}/
        cp ${workDir}/${0} ${baseDir}/${myVENV}/
        echo "source bin/activate" >> ${baseDir}/${myVENV}/.bashrc
        mkdir ${baseDir}/${myVENV}/${appDir}
        chown -R ${myVENV}:${myVENV} ${baseDir}/${myVENV} ${workDir}/${0}
        chmod 700 ${baseDir}/${myVENV}
        echo "cd apps" >> ${baseDir}/${myVENV}/bin/activate
    fi
    echo "su - ${myVENV}"
    echo "sh ${baseDir}/${myVENV}/${0}"
else
##############################################
# for user
##############################################

    # install plugins
    pip install -U pip
    if [ -z ${django_version} ];then
        pip install django
    else
        pip install django==${django_version}
    fi

    # change work directory
    cd ${baseDir}/${myVENV}/${appDir}

    # create project.
    django-admin startproject ${myProj} .

    # set my basic configure: main - settings.py
    sed -i "s/^ALLOWED_HOSTS = .*/ALLOWED_HOSTS = ['*']/" ${myProj}/settings.py
    sed -i "s/^TIME_ZONE = .*/TIME_ZONE = 'Asia\/Seoul'/" ${myProj}/settings.py
    echo "LOGIN_REDIRECT_URL = '/'" >> ${myProj}/settings.py
    sed -i '/^from django.urls import path$/s/$/, include/' ${myProj}/urls.py

    # set my basic configure: main - urls.py, settings.py for apps
    for i in $(seq 0 $(expr ${#myApps[@]} \- 1));do
        python manage.py startapp ${myApps[${i}]}
        sed -i "/^from django.urls import path/a import ${myApps[${i}]}.urls" ${myProj}/urls.py
        sed -i "/'django.contrib.staticfiles',/a \ \ \ \ '${myApps[${i}]}'," ${myProj}/settings.py
        sed -i "/^\]$/i  \ \ \ \ path('${myApps[${i}]}/', include(${myApps[${i}]}.urls))," ${myProj}/urls.py

        # create templates directory for apps
        mkdir ${myApps[${i}]}/templates/

        # create templates directory for css
        mkdir ${myApps[${i}]}/static/
    done
    sed -i "/^\]$/i  \ \ \ \ path('', include(${homeApp}.urls))," ${myProj}/urls.py

    for i in $(seq 0 $(expr ${#myApps[@]} \- 1));do
        # create file: apps - urls.py
        FileName=${myApps[${i}]}/urls.py
        echo 'from django.contrib import admin' > ${FileName}
        echo 'from django.urls import path, include' >> ${FileName}
        echo 'from .views import *' >> ${FileName}
        echo >> ${FileName}
        echo "app_name = \"${myApps[${i}]}\"" >> ${FileName}
        echo 'urlpatterns = [' >> ${FileName}
        echo "    path('', index, name=\"index\")," >> ${FileName}
        echo ']' >> ${FileName}

        # create file: apps - views.py
        FileName=${myApps[${i}]}/views.py
        echo 'from django.shortcuts import render, redirect' > ${FileName}
        echo '# Create your views here.' >> ${FileName}
        echo >> ${FileName}
        echo 'def index(request):' >> ${FileName}
        echo "    return render(request, '${myApps[${i}]}.html')" >> ${FileName}

        # create file: apps for css - main.css
        FileName=${myApps[${i}]}/static/main.css
        echo 'a:link { text-decoration: none; }' > ${FileName}
        echo 'a:visited { text-decoration: none; }' >> ${FileName}
        echo 'a:hover { text-decoration: none; }' >> ${FileName}
        echo 'a:active { text-decoration: none; }' >> ${FileName}

        # create file: apps - base.html
        FileName=${myApps[${i}]}/templates/base.html
        echo '<!DOCTYPE html>' >  ${FileName}
        echo '<html>' >>  ${FileName}
        echo '<body>' >>  ${FileName}

        ##### head #####
        echo '<head>' >> ${FileName}
        echo '        {% load static %}' >> ${FileName}
        echo "        <link rel=\"stylesheet\" href=\"{% static 'main.css' %}\">" >> ${FileName}
        echo '</head>' >> ${FileName}

        ##### Header #####
        echo '<header id="header">' >>  ${FileName}
        echo '        <h1>My First Heading</h1>' >>  ${FileName}
        echo '</header>' >>  ${FileName}

        ##### Home 으로 가기 #####
        echo '<ul>' >> ${FileName}
        echo "<li><a href=\"{% url '${homeApp}:index' %}\" >홈으로</a></li>" >>  ${FileName}
        echo '</ul>' >> ${FileName}

        ##### 로그인 사용자만 노출 #####
        echo '{% if user.is_authenticated %}' >> ${FileName}
        echo '        <!-- 로그인 유저 확인 메시지 -->' >> ${FileName}
        echo '<ul>' >> ${FileName}
        echo '        <li>({{ user }}님 반갑습니다.)</li>' >> ${FileName}
        echo '        <!-- 로그아웃 버튼 -->' >> ${FileName}
        echo "        <li><form method=\"post\" action=\"{% url '${loginApp}:logout' %}\">" >>  ${FileName}
        echo "        {% csrf_token %}" >>  ${FileName}
        echo "        <button type=\"submit\">logout</button></li>" >>  ${FileName}
        echo '</ul>' >> ${FileName}
        #echo "        <a href=\" type=\"submit\">logout</a>" >>  ${FileName}
        echo "</form>" >>  ${FileName}
        ##### 미 로그인 사용자에게로만 노출 #####
        echo '{% else %}' >> ${FileName}
        echo '<ul>' >> ${FileName}
        echo "<li><a href=\"{% url '${loginApp}:login' %}\" >로그인</a></li>" >>  ${FileName}
        echo "<li><a href=\"{% url '${loginApp}:signup' %}\" >회원가입</a></li>" >>  ${FileName}
        echo '</ul>' >> ${FileName}
        echo '{% endif %}' >> ${FileName}

        echo '    {% block content %}' >>  ${FileName}
        echo '	{% endblock %}' >>  ${FileName}

        ##### FOOTER #####
        echo '<myfoot>' >>  ${FileName}
        echo '        부가설명' >>  ${FileName}
        echo '</myfoot>' >>  ${FileName}
        echo >>  ${FileName}
        echo '</body>' >>  ${FileName}
        echo '</html>' >> ${FileName}

        # create file: apps - apps.html
        FileName=${myApps[${i}]}/templates/${myApps[${i}]}.html
        echo '{% extends "base.html" %}' > ${FileName}
        echo '{% block content %}' >> ${FileName}
        echo "<h2>홈</h2>" >> ${FileName}

        echo '{% if user.is_authenticated %}' >> ${FileName}
        echo "        {% if user.username == \"${SuperUser}\" %}" >> ${FileName}
        echo '        ##################################################</br>' >> ${FileName}
        echo '        <mynav>' >>  ${FileName}
        ##### mj app 으로 가기 #####
        echo '        <ul>' >> ${FileName}
        echo "        <li><a href=\"{% url '${homeApp}:index' %}\" >홈으로</a></li>" >>  ${FileName}
        echo "        <li><a href=\"{% url '${mjApp}:index' %}\" >${mjApp} 앱으로</a></li>" >>  ${FileName}
        echo '        </ul>' >> ${FileName}
        echo '        </mynav>' >>  ${FileName}
        echo '        ##################################################</br>' >> ${FileName}
        echo '        {% else %}' >> ${FileName}
        echo '        ##################################################</br>' >> ${FileName}
        echo '        <mynav>' >>  ${FileName}
        echo '        <ul>' >> ${FileName}
        echo "        <li><a href=\"{% url '${homeApp}:index' %}\" >홈으로</a></li>" >>  ${FileName}
        echo '        </ul>' >> ${FileName}
        echo '        </mynav>' >>  ${FileName}
        echo '        </mynav>' >>  ${FileName}
        echo '        ##################################################</br>' >> ${FileName}
        echo '        {% endif %}' >> ${FileName}
        echo '{% else %}' >> ${FileName}
        echo '##################################################</br>' >> ${FileName}
        echo '로그인이 필요합니다.</br>' >> ${FileName}
        echo '##################################################</br>' >> ${FileName}
        echo '{% endif %}' >> ${FileName}
        echo '<p>' >> ${FileName}
        echo "        thisApp: ${myApps[${i}]}" >> ${FileName}
        echo '<p>' >> ${FileName}
        echo '{% endblock %}' >> ${FileName}
    
    done

    #############################################################################
    # Login App
    #############################################################################
    # create file: apps - urls.py for login
    FileName=${loginApp}/urls.py
    echo 'from django.urls import path, include' > ${FileName}
    echo 'from django.contrib.auth import views as auth_views' >> ${FileName}
    echo 'from .views import *' >> ${FileName}
    echo >> ${FileName}
    echo "app_name = '${loginApp}'" >> ${FileName}
    echo >> ${FileName}
    echo 'urlpatterns = [' >> ${FileName}
    echo "    path('', index, name=\"index\")," >> ${FileName}
    echo "    path('login/', auth_views.LoginView.as_view(template_name = \"login.html\"), name = \"login\")," >> ${FileName}
    #echo "    path('logout/', auth_views.LogoutView.as_view(), name = \"logout\")," >> ${FileName}
    echo "    path('logout/', logout, name = \"logout\")," >> ${FileName}
    echo "    path('signup/', signup, name=\"signup\")," >> ${FileName}
    echo ']' >> ${FileName}

    # create file: apps - views.py for login
    FileName=${loginApp}/views.py
    sed -i "1a from django.contrib.auth import login as auth_login" ${FileName}
    sed -i "2a from django.contrib.auth import logout as auth_logout" ${FileName}
    sed -i "2a from django.contrib.auth.forms import UserCreationForm, AuthenticationForm" ${FileName}
    echo "" >> ${FileName}
    echo "def signup(request):" >> ${FileName}
    echo "    if request.user.is_authenticated:" >> ${FileName}
    echo "        return redirect('${homeApp}:index')" >> ${FileName}
    echo "" >> ${FileName}
    echo "    if request.method == 'POST':" >> ${FileName}
    echo "        form = UserCreationForm(request.POST)" >> ${FileName}
    echo "        if form.is_valid():" >> ${FileName}
    echo "            user = form.save()" >> ${FileName}
    echo "            auth_login(request, user)" >> ${FileName}
    echo "            return redirect('${homeApp}:index')" >> ${FileName}
    echo "    else:" >> ${FileName}
    echo "        form = UserCreationForm()" >> ${FileName}
    echo "    context = {" >> ${FileName}
    echo "        'form': form," >> ${FileName}
    echo "    }" >> ${FileName}
    echo "    return render(request, 'signup.html', context)" >> ${FileName}
    echo "" >> ${FileName}
    echo "def login(request):" >> ${FileName}
    echo "    if request.user.is_authenticated:" >> ${FileName}
    echo "        return redirect('${homeApp}:index')" >> ${FileName}
    echo "" >> ${FileName}
    echo "    if request.method == 'POST':" >> ${FileName}
    echo "        form = AuthenticationForm(request, request.POST)" >> ${FileName}
    echo "        if form.is_valid():" >> ${FileName}
    echo "            auth_login(request, form.get_user())" >> ${FileName}
    echo "            return redirect('${homeApp}:index')" >> ${FileName}
    echo "    else:" >> ${FileName}
    echo "        form = AuthenticationForm()" >> ${FileName}
    echo "    context = {" >> ${FileName}
    echo "        'form': form," >> ${FileName}
    echo "    }" >> ${FileName}
    echo "    return render(request, 'login.html', context)" >> ${FileName}
    echo "" >> ${FileName}
    echo "def logout(request):" >> ${FileName}
    echo "    if not request.user.is_authenticated:" >> ${FileName}
    echo "        return redirect('${loginApp}:login')" >> ${FileName}
    echo "" >> ${FileName}
    echo "    auth_logout(request) # 세션 제거 & requset.user 값 초기화" >> ${FileName}
    echo "    return redirect('/home/')" >> ${FileName}

    # create file: apps - login.html for login
    FileName=${loginApp}/templates/login.html
    echo '{% extends "base.html" %}' > ${FileName}
    echo '{% block content %}' >> ${FileName}
    echo '<h2>로그인</h2>' >> ${FileName}
    echo '<div class="container my-3">' >> ${FileName}
    #echo '    {% csrf_token %}' >> ${FileName}
    #echo "    <form method=\"post\" action=\"{% url '${homeApp}:index' %}\">" >> ${FileName}
    echo "    <form method=\"post\">" >> ${FileName}
    echo '        {% csrf_token %}' >> ${FileName}
    echo '        {{ form.as_p }}' >> ${FileName}
    echo '        <!-- <div class="mb-3">' >> ${FileName}
    echo '            <label for="username">사용자 ID</label>' >> ${FileName}
    echo '            <input type="text" class="form-control" name="username" id="username"' >> ${FileName}
    echo "                   value=\"{{ form.username.value|default_if_none:'' }}\">" >> ${FileName}
    echo '        </div>' >> ${FileName}
    echo '        <div class="mb-3">' >> ${FileName}
    echo "            <label for=\"password\">비밀번호</label>" >> ${FileName}
    echo '            <input type="password" class="form-control" name="password" id="password"' >> ${FileName}
    echo "                   value=\"{{ form.password.value|default_if_none:'' }}\">" >> ${FileName}
    echo '        </div> -->' >> ${FileName}
    echo '        <button type="submit" class="btn btn-primary">로그인</button>' >> ${FileName}
    echo '    </form>' >> ${FileName}
    echo '</div>' >> ${FileName}
    echo '{% endblock %}' >> ${FileName}
    
    # create file: apps - logged_out.html for Logout
    FileName=${loginApp}/templates/logged_out.html
    echo '{% extends "base.html" %}' > ${FileName}
    echo '{% block content %}' >> ${FileName}
    echo "<h2>로그아웃</h2>" >> ${FileName}
    echo "<p><a href=\"{%url '${loginApp}:login'%}\">로그인</a></p>" >> ${FileName}
    echo '{% endblock %}' >> ${FileName}

    # create file: apps - signup.html for signup
    FileName=${loginApp}/templates/signup.html
    echo '{% extends "base.html" %}' > ${FileName}
    echo '{% block content %}' >> ${FileName}
    echo '<h2>회원가입</h2>' >> ${FileName}
    echo '<form method="post">' >> ${FileName}
    echo '    {% csrf_token %}' >> ${FileName}
    echo '    {{form.as_p}}' >> ${FileName}
    echo '    <input type="submit" value="회원가입" />' >> ${FileName}
    echo '</form>' >> ${FileName}
    echo '{% endblock %}' >> ${FileName}


    #############################################################################
    # mj App
    #############################################################################
    # create file: apps - mj.html for mjApp
    FileName=${mjApp}/templates/${mjApp}.html
    echo '{% extends "base.html" %}' > ${FileName}
    echo '        {% block content %}' >> ${FileName}
    echo '                {% if user.is_authenticated %}' >> ${FileName}
    echo "                        {% if user.username == \"${SuperUser}\" %}" >> ${FileName}
    echo "                                <h2>${mjApp}</h2>" >> ${FileName}
    #####################################
    ############### TODO: ###############
    #####################################
    echo "                                <p>" >> ${FileName}
	echo "                                you're root" >> ${FileName}
	echo "                                </p>" >> ${FileName}
    echo "                        {% else %}" >> ${FileName}
	echo "                                <p>" >> ${FileName}
	echo "                                you're not root" >> ${FileName}
	echo "                                </p>" >> ${FileName}
    #####################################
    echo '                        {% endif %}' >> ${FileName}
    echo "                {% else %}" >> ${FileName}
	echo "                        <p>" >> ${FileName}
	echo "                        you need login." >> ${FileName}
	echo "                        </p>" >> ${FileName}
    echo '                {% endif %}' >> ${FileName}
    echo '        {% endblock %}' >> ${FileName}


    # change work directory: home
    cd ${baseDir}/${myVENV}/${appDir}/ &> /dev/null

    # sync db
    python manage.py makemigrations
    python manage.py migrate
    #python manage.py syncdb --noinput

    # create superuser: ${SuperUser}/${SuperPassword}
    echo "from django.contrib.auth.models import User; User.objects.create_superuser('${SuperUser}', 'admin@example.com', '${SuperPassword}')" | python manage.py shell

    # create file: run server
    echo '#!/bin/bash' > run
    echo "python manage.py runserver 0.0.0.0:8081" >> run
    chmod 755 run
fi    ##### end: for generic users #####

if [ "${remove_user_afterwork}" == "true" ];then
    rm -f ${workDir}/${0}
    exit 0
fi
exit 1



##### signup
################################
# 1. account 앱 생성 후 urls.py 를 작성
################################
from django.urls import path
from . import views

app_name = 'account'
urlpatterns = [
    path('signup/', views.signup, name='signup'),
]
################################

# 2. views.py 작성
# - GET: 회원가입 폼이 담긴 페이지를 응답
# - POST: 회원가입 정보를 받아서 "유효성 검사" 후 회원가입 진행
#                유효성 검사를 통과하지 못한 경우 에러 메세지를 담아서 출력
# (단, 로그인이 된 상태에서 signup 함수를 실행하려한다면 바로 메인페이지로 이동)
################################
from django.shortcuts import redirect, render
from django.contrib.auth import login as auth_login
from django.contrib.auth.forms import UserCreationForm

def signup(request):
    if request.user.is_authenticated:
        return redirect('home:index')

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            auth_login(request, user)
            return redirect('home:index')
    else:
        form = UserCreationForm()
    context = {
        'form': form,
    }
    return render(request, 'signup.html', context)
################################
# ① request.user.is_authenticated
# : 사용자가 인증되었는지 확인하는 함수.
# User에 항상 True이며, AnonymousUser에 대해서만 항상 False.
# ② UserCreationForm
# : 새로운 유저를 생성해주는 내장 폼
# ③ auth_login (원래 login)
# : 유저 정보를 세션에 생성 및 저장하는 역할을 하는 Django 내장 함수



# 3. templates 작성
################################
{% extends 'base.html' %}
{% block content %}
  <h1>Signup</h1>
  <form action="{% url 'account:signup' %}" method="POST">
    {% csrf_token %}
    {{ form.as_p }}
    <input type="submit">
  </form>
{% endblock content %}
################################
# 완료


# 만약 UsercreationFrom을 수정하고 싶다면
################################
# 4) forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm

# User 모델을 불러오는 2가지 방법 
from django.contrib.auth.models import User # Django 내장 User 모델
from django.conf import settings # => settings.AUTH_USER_MODEL


class CustomUserCreationForm(UserCreationForm):

    class Meta:
        model = User
        # fields = ('username', 'password1', 'password2', 'email')
        fields = UserCreationForm.Meta.fields + ('email',)
################################


##### login
################################
# 1. account 앱 생성 후 urls.py 를 작성
################################
from django.urls import path
from . import views

app_name = 'account'
urlpatterns = [
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('signup/', views.signup, name='signup'),
]
################################


# 2. views.py 작성
# - GET: 로그인 폼이 담긴 페이지를 응답
# - POST: 사용자 정보 받아서 유효성 검사 후 로그인
#        로그인 == 세션 생성 후 DB에 저장
#        유효성 검사 실패 시 에러 메세지 출력
# (단, 로그인이 된 상태에서 login 함수를 실행하려한다면 바로 메인페이지로 이동)
################################
from django.contrib.auth.forms import AuthenticationForm

def login(request):
    if request.user.is_authenticated:
        return redirect('home:index')

    if request.method == 'POST':
        form = AuthenticationForm(request, request.POST)
        if form.is_valid():
            auth_login(request, form.get_user())
            return redirect('home:index')
    else:
        form = AuthenticationForm()
    context = {
        'form': form,
    }
    return render(request, 'login.html', context)
################################
# ① AuthenticationForm
# : 유저가 존재하는지를 검증하는 Django 내장 모델 폼



##### logout
# - POST: 세션 제거
# (단, 로그인이 되지 않은 상태에서 logout 함수를 실행하려한다면 바로 로그인 페이지로 이동)
################################
def logout(request):
    if not request.user.is_authenticated:
        return redirect('account:login')

    auth_logout(request) # 세션 제거 & requset.user 값 초기화
    return redirect('/home/')
################################
# ① auth_logout (원래 logout)
# : 현재 요청에 대한 db의 세션 데이터를 삭제하고 클라이언트 쿠키에서도 sessionid를 삭제하는 함수


# login templates
################################
{% extends 'base.html' %}
{% block content %}
  <h1>Login</h1>
  <form action="" method="POST">
    {% csrf_token %}
    {{ form.as_p }}
    <input type="submit">
  </form>
{% endblock content %}
################################


##### update/delete users
################################
# 1. urls
################################
from django.urls import path
from . import views

app_name = 'account'
urlpatterns = [
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('signup/', views.signup, name='signup'),
    path('delete/', views.delete, name='delete'),
    path('update/', views.update, name='update'),
]
################################

################################
# 2. update
# - GET: 정보 수정 폼이 담긴 페이지를 응답
# - POST: 사용자 정보 받아서 유효성 검사 후 정보수정
################################
from django.contrib.auth.forms import UserChangeForm
from django.views.decorators.http import require_GET, require_POST

def update(request):
    if request.method == 'POST':
        form = UserChangeForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            return redirect('home:index')
    else:
        form = UserChangeForm(instance=request.user)
    context = {
        'form': form,
    }
    return render(request, 'update.html', context)
################################
# ① UserChangeForm
# : 유저의 정보를 수정하는 장고 내장 폼


################################
# 3. delete
# - POST: 유저 정보 제거, 세션 제거
################################
from django.views.decorators.http import require_GET, require_POST

@require_POST
def delete(request):
    if request.user.is_authenticated:
        request.user.delete()
        auth_logout(request)
    return redirect('home:index')
################################

################################
# 4. templates
################################
{% extends 'base.html' %}

{% block content %}
  <h1>회원정보수정</h1>
  <form action="{% url 'account:update' %}" method="POST">
    {% csrf_token %}
    {{ form.as_p }}
    <input type="submit">
  </form>
{% endblock content %}
################################

################################
# 5. forms
# : UserChangeForm을 수정한 CustomUserChangeForm 생성
################################
from django.contrib.auth.forms import UserChangeForm
from django.contrib.auth import get_user_model

class CustomUserChangeForm(UserChangeForm):

    class Meta:
        model = get_user_model()
        fields = ('email', 'first_name', 'last_name',)
################################
