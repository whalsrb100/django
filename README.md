# virtual Environment: django

나의 django 환경 만들기 스크립트임.

```bash
#!/bin/bash


baseDir="/root/venv"
myVENV="mj_001"
myProj="main"
myApps=(
    "home"
    "accounts"
)

isContinue=yes
if [ ! -d ${baseDir} ];then
    mkdir ${baseDir}/
else
    echo "Exists directory \"${baseDir}\"."
    echo -n "Do you want continue process ?(y/N) "
    read INPUT
    INPUT=$(echo "${INPUT}" | tr [:upper:] [:lower:])
    case ${INPUT} in
    "y"|"yes") 
             pass ;;
    "n"|"no")
        rm -rf ${baseDir}/
        mkdir ${baseDir}/ ::
    *) pass ::
    esac
fi

cd ${baseDir}/

python3 -m venv ${myVENV}
cd ${myENV}/

source bin/activate
pip install -U pip
pip install django

mkdir django
cd django/

django-admin startproject ${myProj} .

cd ${myProj}/
sed -i "s/^ALLOWED_HOSTS = .*/ALLOWED_HOSTS = ['*']/" settings.py
sed -i "s/^TIME_ZONE = .*/TIME_ZONE = 'Asia\/Seoul'/" settings.py
sed -i '/^from django.urls import path$/s/$/, include/' urls.py

for i in $(seq 0 $(expr ${#myApps[@]} \- 1));do
    cd ..
    python manage.py startapp ${myApps[${i}]}
    cd ${myProj}/
    sed -i "/'django.contrib.staticfiles',/a \ \ \ \ '${myApps[${i}]}'," settings.py
    sed -i "/^\]$/i  \ \ \ \ path('${myApps[${i}]}/', include(${myApps[${i}]}.urls))," urls.py
done
```