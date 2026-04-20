
{% assign display_property = true %}

{% comment %} <!-- BEGIN Iterate Physical Dictionary Surfaces --> {% endcomment %}
{% for surf_obj in DICTIONARY_SURF %}

{% comment %} <!-- BEGIN PID Processing --> {% endcomment %}
{% if surf_obj[1].pid == MITRE_PID %}
{% assign display_surface = true %}

{% comment %} <!-- BEGIN Iterate Physical Dictionary Vectors --> {% endcomment %}
{% for vect_obj in DICTIONARY_VECT %}
{% assign display_vector = true %}


{% comment %} <!-- BEGIN Iterate All ADs --> {% endcomment %}
{% for ad in DATABASE_AD %}

{% for ad_surf in ad[1].surf %}
{% if DISPLAY_ALL_ADS == false %}
{% if ad_surf == ad[1].surf[0] %}
{% comment %} <!-- Only consider the most significant surface --> {% endcomment %}
{% else %}
{% continue %}
{% endif %}
{% endif %}
{% if surf_obj[0] == ad_surf or surf_obj[1].alias contains ad_surf %}

{% if vect_obj[0] contains ad[1].vect[0] or vect_obj[1].alias contains ad[1].vect[0] %}

{% comment %} <!-- BEGIN Display NON-EMPTY stuff --> {% endcomment %}
{% if display_property == true %}
{% assign display_property = false %}
{% if MITRE_PID %}
{% comment %} {{ MITRE_PROPERTY[0].name }} (<a href="https://emb3d.mitre.org/properties-mapper/?id={{ MITRE_PIDS }}" target="_blank">MITRE EM3ED {{ MITRE_PIDS }}</a>) {% endcomment %}
{% else %}
{% comment %} ADF-Only Surfaces (No MITRE EM3ED PID) {% endcomment %}
{% endif %}
{% endif %}

{% if display_surface == true %}
{% assign display_surface = false %}
{% comment %}
{{ surf_obj[0] }}
  * Keys: {{ surf_obj[0] }} {% for alias in surf_obj[1].alias %} \| {{ alias }}{% endfor %}
  * Description: {{ surf_obj[1].description }}
  * Attack Vectors and Threats:
{% endcomment %}
{% endif %}

{% if display_vector == true %}
{% assign display_vector = false %}
{% if vect_obj[1].tid %}
<tr><td> {{ vect_obj[0] }}  </td><td> <a href="https://emb3d.mitre.org/threats/TID-{{ vect_obj[1].tid }}.html" target="_blank">MITRE EM3ED TID-{{ vect_obj[1].tid }}</a> </td><td> n/a </td></tr>
{% endif %}
{% endif %}

{% assign risk_value = ad[1].risk  %}

{% if risk_value >= 7 and risk_value <= 10 %}
{% assign risk_severity_class = "risk_severity_high" %}
{% elsif risk_value >= 4 %}
{% assign risk_severity_class = "risk_severity_medium" %}
{% elsif risk_value >= 0 %}
{% assign risk_severity_class = "risk_severity_low" %}
{% else %}
{% assign risk_severity_class = "risk_severity_none" %}
{% endif %}

<tr><td> <a href="{{ DIR_AD }}/{{ ad[0] }}.html">{{ ad[1].a }}</a>  </td><td> {% if vect_obj[1].tid %} <a href="https://emb3d.mitre.org/threats/TID-{{ vect_obj[1].tid }}.html" target="_blank">MITRE EM3ED TID-{{ vect_obj[1].tid }}</a> {% endif %} </td><td class="{{ risk_severity_class }}"> {% if ad[1].risk %} {{ ad[1].risk }} {% else %} n/a {% endif %} </td></tr>

{% comment %} <!-- END Display NON-EMPTY stuff --> {% endcomment %}

{% endif %}
{% endif %}
{% endfor %}

{% endfor %}
{% comment %} <!-- END Iterate All ADs --> {% endcomment %}


{% endfor %}
{% comment %} <!-- BEGIN Iterate Physical Dictionary Vectors --> {% endcomment %}

{% endif %}
{% comment %} <!-- END PID Processing --> {% endcomment %}


{% endfor %}
{% comment %} <!-- END Iterate Physical Dictionary Surfaces --> {% endcomment %}



{% comment %} <!-- BEGIN Display Non-covered MITRE surfaces --> {% endcomment %}
{% if display_property == true %}
{% comment %} EM3ED-only: {{ MITRE_PROPERTY[0].name }} (<a href="https://emb3d.mitre.org/properties-mapper/?id={{ MITRE_PIDS }}" target="_blank">MITRE EM3ED {{ MITRE_PIDS }}</a>) {% endcomment %}

{% endif %}

{% for prop in MITRE_PROPERTY %}
{% assign mitre_relationships = site.data.emb3d.objects | where: "type", "relationship" | where: "source_ref", prop.id %}

{% for rel in mitre_relationships %}

{% assign mitre_vulnerabilities = site.data.emb3d.objects | where: "type", "vulnerability" | where: "id", rel.target_ref %}

{% for vuln in mitre_vulnerabilities %}

<tr><td> {{ vuln.name }}  </td><td> <a href="https://emb3d.mitre.org/threats/{{ vuln.x_mitre_emb3d_threat_id }}.html" target="_blank">MITRE EM3ED {{ vuln.x_mitre_emb3d_threat_id }} </a> </td><td> n/a </td></tr>

{% endfor %}
{% endfor %}
{% endfor %}
{% comment %} <!-- END Display Non-covered MITRE surfaces --> {% endcomment %}

