---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

layout: default
custom_js:
  - sortable.min.js
---

# Software Threat Catalog

<table id="threatCatalog" data-sortable>
<thead><tr><th>Attack Vector and Threat</th><th>Primary MITRE EMB3D TID</th><th>Risk Value</th></tr></thead>

{% comment %} <!-- BEGIN Iterate Defined Surfaces --> {% endcomment %}
{% for surface in site.data.model_bt %}


{% comment %} <!-- BEGIN Settings --> {% endcomment %}
{% assign DICTIONARY_SURF = site.data.dicts.software.surf %}
{% assign DICTIONARY_VECT = site.data.dicts.software.vect %}
{% assign DATABASE_AD = site.data.ad.software %}
{% assign DIR_AD = "ad_software" %}  {% comment %} <!-- Directory where generated AD pages are stored --> {% endcomment %}
{% assign DISPLAY_ALL_ADS =  false %}  {% comment %} <!-- Display all relations between ADs and surfaces --> {% endcomment %}
{% assign MITRE_PID = surface[1].pid %}
{% assign MITRE_PIDS = "PID-" | append: surface[1].pid %}
{% assign MITRE_PROPERTY = site.data.emb3d.objects | where: "type", "x-mitre-emb3d-property" | where: "x_mitre_emb3d_property_id", MITRE_PIDS %}
{% comment %} <!-- END Settings --> {% endcomment %}


{% include display_catalog.md %}

{% endfor %}
{% comment %} <!-- END Iterate Defined Surfaces --> {% endcomment %}

</table>
