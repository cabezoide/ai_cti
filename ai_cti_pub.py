#!/usr/bin/env python3
import sys
import openai
import json
import requests
import feedparser
import pandas as pd
import datetime
import dateutil.parser
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# Credenciales de API ChatGPT
openai.api_key = "AQUI_VA_TU_API_KEY_DE_OPENAI"

# Timestamps
today = datetime.datetime.now()
formatted_today_date = today.strftime("%Y-%m-%d")
timestamp = today.strftime("%d-%m-%Y_%H%M%S")
print(timestamp)


# Lista de url de feed rss

rss_url = [
    "https://blog.rapid7.com/rss/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.curatedintel.org/feeds/posts/default",
    "http://feeds.feedburner.com/darknethackers",
    "https://gbhackers.com/feed/",
    "https://www.proofpoint.com/us/threat-insight-blog.xml",
    "https://blog.gigamon.com/feed/",
    "https://www.certsi.es/feed/avisos-seguridad/all",
    "http://www.hackingarticles.in/feed/",
    "http://blog.crowdstrike.com/feed",
    "http://seguridadyredes.wordpress.com/feed/",
    "https://bushidotoken.blogspot.com/feeds/posts/default",
    "https://www.coveware.com/blog?format=RSS",
    "https://www.huntress.com/blog/rss.xml",
    "http://feeds.feedburner.com/dragonjar/pKru",
    "http://feeds.feedburner.com/FluProject",
    "https://pduchement.wordpress.com/feed/",
    "https://www.cybereason.com/blog/rss.xml",
    "http://www.exploit-db.com/rss.php",
    "http://feeds.feedburner.com/PentestTools",
    "http://www.securelist.com/en/rss/allupdates",
    "https://techcrunch.com/author/zack-whittaker/feed/",
    "https://ciberseguridad.blog/rss/",
    "http://blog.jpcert.or.jp/atom.xml",
    "https://therecord.media/feed/",
    "https://bellingcat.com/feed/",
    "https://www.proofpoint.com/rss.xml",
    "https://www.ciberseguridadlatam.com/feed/",
    "http://www.darkreading.com/rss/all.xml",
    "http://www.bleepingcomputer.com/feed/",
    "http://feeds.feedblitz.com/alienvault-security-essentials",
    "http://feeds.trendmicro.com/TrendMicroResearch",
    "http://iscxml.sans.org/rssfeed.xml",
    "http://feeds.feedblitz.com/alienvault-blogs&amp;x=1",
    "https://thedfirreport.com/feed/",
    "http://www.seguridadyfirewall.cl/feeds/posts/default",
    "https://expel.io/feed/",
    "https://www.recordedfuture.com/feed/",
    "https://blog.google/threat-analysis-group/rss",
    "http://cyberseguridad.net/index.php?format=feed&amp;type=rss",
    "http://feeds.feedburner.com/andreafortuna",
    "https://labs.sentinelone.com/feed/",
    "https://www.blogger.com/feeds/4838136820032157985/posts/default",
    "https://hackerone.com/news.rss",
    "https://s4vitar.github.io/feed.xml",
    "https://dragos.com/feed/",
    "https://stairwell.com/feed/atom/",
    "http://www.volexity.com/blog/?feed=rss2",
    "https://www.secureworks.com/rss?feed=blog",
    "https://forensicitguy.github.io/feed.xml",
    "http://www.seguridadjabali.com/feeds/posts/default",
    "http://threatpost.com/feed",
    "http://blog.morphisec.com/rss.xml",
    "https://www.tarlogic.com/feed",
    "http://pax0r.com/feed/",
    "http://thehackerway.com/feed/",
    "http://vrt-sourcefire.blogspot.com/feeds/posts/default",
    "https://www.redcanary.com/blog/feed/",
    "http://blogs.technet.com/msrc/rss.xml",
    "https://www.maltego.com/index.xml",
    "http://researchcenter.paloaltonetworks.com/feed/",
    "https://www.ciberseguridadpyme.es/feed/",
    "http://www.us-cert.gov/current/index.rdf",
    "https://citizenlab.org/category/lab-news/feed/",
    "https://posts.specterops.io/feed",
    "https://www.brighttalk.com/channel/7451/feed/rss",
    "https://www.greynoise.io/blog/rss.xml",
    "http://cybersecuritynews.es/feed/",
    "http://www.intezer.com/feed/",
    "http://blog.emsisoft.com/feed/",
    "http://blog.eset.com/feed",
    "https://exchange.xforce.ibmcloud.com/rss/collection?tag=advisory/>",
    "http://blogs.technet.com/mmpc/rss.xml",
    "https://www.ccn-cert.cni.es/component/obrss/rss-noticias.feed",
    "https://www.ccn-cert.cni.es/component/obrss/rss-ultimas-vulnerabilidades.feed"]


def consulta_chatgpt(text):
    """Funcion que consulta a chatgpt"""
    # Obtener texto del mensaje
    text = str(text)

    # Crear solicitud a la API de ChatGPT
    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {openai.api_key}"}
    data = json.dumps({
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "%s" % text}],
        "temperature": 0,
        "max_tokens": 1500,
        "top_p": 1,
        "frequency_penalty": 0,
        "presence_penalty": 0,
    })
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        data=data)

    # Procesar respuesta de la API de ChatGPT
    response_json = response.json()
    reply_text = response_json["choices"][0]["message"]["content"]
    return reply_text


def obtain_rss_feed(rss_url):
    feeds = []
    for url in rss_url:
        print(url)
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:

                title = entry.title
                link = entry.link
                date = entry.published
                formatted_date = dateutil.parser.parse(
                    date, ignoretz=True).date()

                feeds.append(
                    {"title": title, "link": link, "date": formatted_date})
        except BaseException:
            continue
    return feeds


def genera_respuesta():

    # Obtener arreglo de todos los feed
    print("### Obteniendo feeds ###")
    total_feeds = obtain_rss_feed(rss_url)

    # Convertir arreglo de todos los feed a pandas dataframe
    print("### Convertir a pandas dataframe ###")
    df = pd.DataFrame(total_feeds)

    # Remover caracteres no ASCII
    print("### Remover caracteres no ASCII ###")
    df = df.applymap(
        lambda x: x.encode(
            'ascii',
            'ignore').decode() if isinstance(
            x,
            str) else x)
    # print(df.head(20))

    print("### Filtrar por la fecha de hoy ###")
    # Es necesario copiar el df para evitar errores de chained index
    df_copy = df.copy()
    # Pasar a fecha estandar
    df_copy['date'] = pd.to_datetime(df['date'])

    # Crear mascara de DataFrame, solo nos interesa filtrar las noticias con
    # fecha de [hoy]
    df_mask = df_copy['date'] == formatted_today_date
    # Para filtrar por fecha especifica: df_mask=df_copy['date'] == "2023-04-26"
    # Aplicamos mascara
    df_filtrado = df[df_mask]
    print(df_filtrado.head(50))
    # Guardar Dataframe filtrado como string
    string_df = df_filtrado.to_string(index=False, max_rows=50)
    print(string_df)

    # Generar Prompt para ChatGPT
    print("### Generar Prompt ###")
    texto = f"Lee hasta el final antes de generar la salida. Toma el rol de un analista de ciberseguridad, con mucha experiencia, leyendo titulares de noticias.  Le interesan solo los titulares que tienen relacion con malware y exploit. Tambien vulnerabilidades criticas en Cisco, Juniper, Huawei, Microsoft, Linux, VMware, Fortinet. Tambien le interesan titulares con palabras clave: Zero day, APT, Latinoamerica, Chile, CVE criticos. Entregame como salida el body de una tabla en formato html con 2 columnas titular y url, solo con los titulares que le interesan y su URL original. Solo los titulares traducelos a español. Restricciones: no inventes titulares ni url, si no hay noticias de interes indica que no hay noticias. La tabla de titulares de noticias es esta: {string_df}"

    # Llamar a funcion que consulta en ChatGPT
    print("### Consultando en ChatGPT ###")
    respuesta = str(consulta_chatgpt(texto))
    if len(respuesta) == 0:
        respuesta = "No hay noticias actuales de interes"

    # Defang de URL
    respuesta = respuesta.replace("http://", "http[:]//")
    respuesta = respuesta.replace("https://", "https[:]//")
    respuesta = respuesta.replace(".", "[.]")
    return respuesta


def envia_correo(respuesta):
    print("### Mandar Correo ###")
    cantidad_rss_url = len(rss_url)

    msg = MIMEMultipart('alternative')
    # CASILLA DE CORREO ORIGEN
    msg['From'] = "correo_origen@dominio.com"
    # CASILLAS DE CORREO DESTINO
    msg['To'] = "correo_destino1@dominio.com, correo_destino2@gmail.com, correo_destino3@gmail.com"

    msg['Subject'] = "Reporte IA de CiberAmenazas %s" % timestamp

    html = f"""\
    <!DOCTYPE html>
    <html>
      <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style type="text/css">
          h2{{font-family: sans-serif;font-size:20px;color:#0A31AF;}}
          p{{font-family: sans-serif;font-size: 12px;}}
          td{{vertical-align:top}}
          body {{font-family: sans-serif; font-size: 12px;}}
          table {{
                 border-collapse: collapse;
                 width: 100%;
                }}
          td {{
              border: 1px solid black;
              padding: 8px;
              text-align: left;
             }}
        </style>
    </head>

        <h2>Reporte IA de CiberAmenazas</h2>
        <p>Estimados, <br> Se adjunta Reporte IA de CiberAmenazas, obtenido desde {cantidad_rss_url} Feed RSS de ciberseguridad, y analizados por inteligencia artificial <br>
                     Criterios de interes: Malware, Exploit, Cisco, Juniper, Huawei, Microsoft, Linux, VMware, Zero day, APT, Latinoamerica, Chile, CVE criticos y Vulnerabilidades criticas <br>
           {respuesta}
       </p>
      </body>
    </html>
    """

    part1 = MIMEText(html, 'html')
    msg.attach(part1)
    # ESPECIFICAR SERVIDOR DE SMTP RELAY USADO PARA ENVIAR CORREOS
    s = smtplib.SMTP('servidor_relay.dominio.com')
    s.sendmail(msg['From'], msg['To'].split(","), msg.as_string())
    s.quit()


if __name__ == "__main__":
    envia_correo(genera_respuesta())
