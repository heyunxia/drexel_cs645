if (${?CLASSPATH} == 0) then
    setenv CLASSPATH
fi
setenv CLASSPATH ${CLASSPATH}:.:iaik_jce.jar
