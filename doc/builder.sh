

sphinx-apidoc -f -o source/ ../ 
sphinx-apidoc -f -o source/plugins/ ../plugins
sphinx-apidoc -f -o source/clients/ ../clients
make html
