# -*- coding: utf-8 -*-

"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2010 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from future import standard_library

import os
import optparse
import socket
import sys
import re
import logging
from builtins import object
from builtins import *
standard_library.install_aliases()


class NICClient(object):

    ABUSEHOST = "whois.abuse.net"
    NICHOST = "whois.crsnic.net"
    INICHOST = "whois.networksolutions.com"
    DNICHOST = "whois.nic.mil"
    GNICHOST = "whois.nic.gov"
    ANICHOST = "whois.arin.net"
    LNICHOST = "whois.lacnic.net"
    RNICHOST = "whois.ripe.net"
    PNICHOST = "whois.apnic.net"
    MNICHOST = "whois.ra.net"
    QNICHOST_TAIL = ".whois-servers.net"
    SNICHOST = "whois.6bone.net"
    BNICHOST = "whois.registro.br"
    NORIDHOST = "whois.norid.no"
    IANAHOST = "whois.iana.org"
    PANDIHOST = "whois.pandi.or.id"
    DENICHOST = "de.whois-servers.net"
    AI_HOST = "whois.nic.ai"
    AR_HOST = "whois.nic.ar"
    BY_HOST = "whois.cctld.by"
    HR_HOST = "whois.dns.hr"
    APP_HOST = "whois.nic.google"
    DEV_HOST = "whois.nic.google"
    GAMES_HOST = "whois.nic.games"
    PAGE_HOST = "whois.nic.page"
    CL_HOST = "whois.nic.cl"
    CR_HOST = "whois.nic.cr"
    DE_HOST = "whois.denic.de"
    DK_HOST = "whois.dk-hostmaster.dk"
    DO_HOST = "whois.nic.do"
    CA_HOST = "whois.ca.fury.ca"
    HK_HOST = "whois.hkirc.hk"
    HN_HOST = "whois.nic.hn"
    KZ_HOST = "whois.nic.kz"
    DEFAULT_PORT = "nicname"
    MONEY_HOST = "whois.nic.money"
    JOBS_HOST = "whois.nic.jobs"
    LAT_HOST = "whois.nic.lat"
    LI_HOST = "whois.nic.li"
    MX_HOST = "whois.mx"
    PE_HOST = "kero.yachay.pe"
    ONLINE_HOST = "whois.nic.online"
    IST_HOST = "whois.afilias-srs.net"
    # Additional Whois Servers
    ABOGADO_HOST = "whois.nic.abogado"
    ACCOUNTANT_HOST = "whois.nic.accountant"
    AERO_HOST = "whois.aero"
    AG_HOST = "whois.nic.ag"
    AI_HOST = "whois.nic.ai"
    ALLFINANZ_HOST = "whois.nic.allfinanz"
    ALSACE_HOST = "whois.nic.alsace"
    AM_HOST = "whois.amnic.net"
    AMSTERDAM_HOST = "whois.nic.amsterdam"
    AQUARELLE_HOST = "whois-aquarelle.nic.fr"
    AS_HOST = "whois.nic.as"
    ASIA_HOST = "whois.nic.asia"
    AU_HOST = "whois.audns.net.au"
    AW_HOST = "whois.nic.aw"
    AX_HOST = "whois.ax"
    BANK_HOST = "whois.nic.bank"
    BAR_HOST = "whois.nic.bar"
    BARCLAYCARD_HOST = "whois.nic.barclaycard"
    BARCLAYS_HOST = "whois.nic.barclays"
    BAYERN_HOST = "whois.nic.bayern"
    BEER_HOST = "whois.nic.beer"
    BERLIN_HOST = "whois.nic.berlin"
    BI_HOST = "whois1.nic.bi"
    BID_HOST = "whois.nic.bid"
    BIO_HOST = "whois.nic.bio"
    BMW_HOST = "whois.nic.bmw"
    BIZ_HOST = "whois.biz"
    BJ_HOST = "whois.nic.bj"
    BLOG_HOST = "whois.nic.blog"
    BRUSSELS_HOST = "whois.nic.brussels"
    BUDAPEST_HOST = "whois.nic.budapest"
    BUILD_HOST = "whois.nic.build"
    BUZZ_HOST = "whois.nic.buzz"
    BW_HOST = "whois.nic.net.bw"
    BY_HOST = "whois.cctld.by"
    BZH_HOST = "whois-bzh.nic.fr"
    CA_HOST = "whois.cira.ca"
    CAM_HOST = "whois.nic.cam"
    CANCERRESEARCH_HOST = "whois.nic.cancerresearch"
    CAPETOWN_HOST = "capetown-whois.registry.net.za"
    CAREER_HOST = "whois.nic.career"
    CASA_HOST = "whois.nic.casa"
    CAT_HOST = "whois.cat"
    CC_HOST = "ccwhois.verisign-grs.com"
    CH_HOST = "whois.nic.ch"
    CI_HOST = "whois.nic.ci"
    CL_HOST = "whois.nic.cl"
    CLOUD_HOST = "whois.nic.cloud"
    CLUB_HOST = "whois.nic.club"
    CM_HOST = "whois.netcom.cm"
    COLOGNE_HOST = "whois.nic.cologne"
    COOKING_HOST = "whois.nic.cooking"
    COOP_HOST = "whois.nic.coop"
    CRICKET_HOST = "whois.nic.cricket"
    CUISINELLA_HOST = "whois.nic.cuisinella"
    CX_HOST = "whois.nic.cx"
    CYMRU_HOST = "whois.nic.cymru"
    CZ_HOST = "whois.nic.cz"
    DATE_HOST = "whois.nic.date"
    DE_HOST = "whois.denic.de"
    DESI_HOST = "whois.nic.desi"
    DK_HOST = "whois.dk-hostmaster.dk"
    DM_HOST = "whois.nic.dm"
    DO_HOST = "whois.nic.do"
    DOWNLOAD_HOST = "whois.nic.download"
    DURBAN_HOST = "durban-whois.registry.net.za"
    DVAG_HOST = "whois.nic.dvag"
    EE_HOST = "whois.tld.ee"
    EU_HOST = "whois.eu"
    EUROVISION_HOST = "whois.nic.eurovision"
    EUS_HOST = "whois.nic.eus"
    FAITH_HOST = "whois.nic.faith"
    FASHION_HOST = "whois.nic.fashion"
    FI_HOST = "whois.fi"
    FILM_HOST = "whois.nic.film"
    FIRMDALE_HOST = "whois.nic.firmdale"
    FISHING_HOST = "whois.nic.fishing"
    FIT_HOST = "whois.nic.fit"
    FLSMIDTH_HOST = "whois.nic.flsmidth"
    FRL_HOST = "whois.nic.frl"
    FROGANS_HOST = "whois.nic.frogans"
    GA_HOST = "whois.dot.ga"
    GAL_HOST = "whois.nic.gal"
    GAMES_HOST = "whois.nic.games"
    GARDEN_HOST = "whois.nic.garden"
    GD_HOST = "whois.nic.gd"
    GDN_HOST = "whois.nic.gdn"
    GENT_HOST = "whois.nic.gent"
    GG_HOST = "whois.gg"
    GL_HOST = "whois.nic.gl"
    GLOBAL_HOST = "whois.nic.global"
    GMX_HOST = "whois.nic.gmx"
    GOLD_HOST = "whois.nic.gold"
    GOP_HOST = "whois.nic.gop"
    GOV_HOST = "whois.nic.gov"
    GQ_HOST = "whois.dominio.gq"
    GY_HOST = "whois.registry.gy"
    HAMBURG_HOST = "whois.nic.hamburg"
    HN_HOST = "whois.nic.hn"
    HORSE_HOST = "whois.nic.horse"
    HR_HOST = "whois.dns.hr"
    HT_HOST = "whois.nic.ht"
    HU_HOST = "whois.nic.hu"
    IBM_HOST = "whois.nic.ibm"
    IE_HOST = "whois.domainregistry.ie"
    IFM_HOST = "whois.nic.ifm"
    IM_HOST = "whois.nic.im"
    INT_HOST = "whois.iana.org"
    IO_HOST = "whois.nic.io"
    IS_HOST = "whois.isnic.is"
    IT_HOST = "whois.nic.it"
    JAVA_HOST = "whois.nic.java"
    JE_HOST = "whois.je"
    JETZT_HOST = "whois.nic.jetzt"
    JOBS_HOST = "whois.nic.jobs"
    JOBURG_HOST = "joburg-whois.registry.net.za"
    KI_HOST = "whois.nic.ki"
    KIWI_HOST = "whois.nic.kiwi"
    KOELN_HOST = "whois.nic.koeln"
    KY_HOST = "whois.kyregistry.ky"
    LA_HOST = "whois.nic.la"
    LACAIXA_HOST = "whois.nic.lacaixa"
    LAT_HOST = "whois.nic.lat"
    LATROBE_HOST = "whois.nic.latrobe"
    LECLERC_HOST = "whois-leclerc.nic.fr"
    LI_HOST = "whois.nic.li"
    LIVE_HOST = "whois.nic.live"
    LOAN_HOST = "whois.nic.loan"
    LONDON_HOST = "whois.nic.london"
    LT_HOST = "whois.domreg.lt"
    LU_HOST = "whois.dns.lu"
    LUXE_HOST = "whois.nic.luxe"
    LUXURY_HOST = "whois.nic.luxury"
    MA_HOST = "whois.iam.net.ma"
    MADRID_HOST = "whois.madrid.rs.corenic.net"
    MANGO_HOST = "whois.nic.mango"
    MD_HOST = "whois.nic.md"
    ME_HOST = "whois.nic.me"
    MEN_HOST = "whois.nic.men"
    MENU_HOST = "whois.nic.menu"
    MG_HOST = "whois.nic.mg"
    MIAMI_HOST = "whois.nic.miami"
    MINI_HOST = "whois.nic.mini"
    ML_HOST = "whois.dot.ml"
    MO_HOST = "whois.monic.mo"
    MOE_HOST = "whois.nic.moe"
    MONASH_HOST = "whois.nic.monash"
    MOSCOW_HOST = "whois.nic.moscow"
    MS_HOST = "whois.nic.ms"
    MU_HOST = "whois.nic.mu"
    MUSEUM_HOST = "whois.museum"
    NA_HOST = "whois.na-nic.com.na"
    NAME_HOST = "whois.nic.name"
    NC_HOST = "whois.nc"
    NEWS_HOST = "whois.nic.news"
    NF_HOST = "whois.nic.nf"
    NL_HOST = "whois.domain-registry.nl"
    NO_HOST = "whois.norid.no"
    NRW_HOST = "whois.nic.nrw"
    NU_HOST = "whois.iis.nu"
    NYC_HOST = "whois.nic.nyc"
    ONE_HOST = "whois.nic.one"
    ONLINE_HOST = "whois.nic.online"
    OOO_HOST = "whois.nic.ooo"
    OVH_HOST = "whois-ovh.nic.fr"
    PARIS_HOST = "whois-paris.nic.fr"
    PARTY_HOST = "whois.nic.party"
    PF_HOST = "whois.registry.pf"
    PHYSIO_HOST = "whois.nic.physio"
    PLUS_HOST = "whois.nic.plus"
    PM_HOST = "whois.nic.pm"
    POHL_HOST = "whois.nic.pohl"
    POST_HOST = "whois.dotpostregistry.net"
    QPON_HOST = "whois.nic.qpon"
    QUEBEC_HOST = "whois.nic.quebec"
    RACING_HOST = "whois.nic.racing"
    RE_HOST = "whois.nic.re"
    REISE_HOST = "whois.nic.reise"
    REVIEW_HOST = "whois.nic.review"
    RODEO_HOST = "whois.nic.rodeo"
    RUHR_HOST = "whois.nic.ruhr"
    SAMSUNG_HOST = "whois.nic.samsung"
    SAARLAND_HOST = "whois.nic.saarland"
    SB_HOST = "whois.nic.sb"
    SCA_HOST = "whois.nic.sca"
    SCB_HOST = "whois.nic.scb"
    SCHMIDT_HOST = "whois.nic.schmidt"
    SCIENCE_HOST = "whois.nic.science"
    SCOT_HOST = "whois.nic.scot"
    SE_HOST = "whois.iis.se"
    SH_HOST = "whois.nic.sh"
    SI_HOST = "whois.arnes.si"
    SK_HOST = "whois.sk-nic.sk"
    SKY_HOST = "whois.nic.sky"
    SM_HOST = "whois.nic.sm"
    SN_HOST = "whois.nic.sn"
    SO_HOST = "whois.nic.so"
    SPIEGEL_HOST = "whois.nic.spiegel"
    ST_HOST = "whois.nic.st"
    STREAM_HOST = "whois.nic.stream"
    STUDY_HOST = "whois.nic.study"
    SUCKS_HOST = "whois.nic.sucks"
    SURF_HOST = "whois.nic.surf"
    SX_HOST = "whois.sx"
    SYDNEY_HOST = "whois.nic.sydney"
    TAIPEI_HOST = "whois.nic.taipei"
    TATAR_HOST = "whois.nic.tatar"
    TC_HOST = "whois.nic.tc"
    TEL_HOST = "whois.nic.tel"
    TF_HOST = "whois.nic.tf"
    TIROL_HOST = "whois.nic.tirol"
    TK_HOST = "whois.dot.tk"
    TL_HOST = "whois.nic.tl"
    TM_HOST = "whois.nic.tm"
    TOP_HOST = "whois.nic.top"
    TR_HOST = "whois.nic.tr"
    TRADE_HOST = "whois.nic.trade"
    TRAVEL_HOST = "whois.nic.travel"
    TRUST_HOST = "whois.nic.trust"
    TUI_HOST = "whois.nic.tui"
    TV_HOST = "tvwhois.verisign-grs.com"
    UNO_HOST = "whois.nic.uno"
    US_HOST = "whois.nic.us"
    UZ_HOST = "whois.cctld.uz"
    VERSICHERUNG_HOST = "whois.nic.versicherung"
    VG_HOST = "whois.nic.vg"
    VIP_HOST = "whois.nic.vip"
    VLAANDEREN_HOST = "whois.nic.vlaanderen"
    VODKA_HOST = "whois.nic.vodka"
    VOTING_HOST = "whois.voting.tld-box.at"
    WALES_HOST = "whois.nic.wales"
    WEBCAM_HOST = "whois.nic.webcam"
    WED_HOST = "whois.nic.wed"
    WEDDING_HOST = "whois.nic.wedding"
    WF_HOST = "whois.nic.wf"
    WHOSWHO_HOST = "whois.nic.whoswho"
    WIEN_HOST = "whois.nic.wien"
    WIN_HOST = "whois.nic.win"
    WORK_HOST = "whois.nic.work"
    WS_HOST = "whois.website.ws"
    WTC_HOST = "whois.nic.wtc"
    XXX_HOST = "whois.nic.xxx"
    YOGA_HOST = "whois.nic.yoga"
    YT_HOST = "whois.nic.yt"
    ZM_HOST = "whois.nic.zm"


    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

    def __init__(self):
        self.use_qnichost = False

    def findwhois_server(self, buf, hostname, query):
        """Search the initial TLD lookup results for the regional-specifc
        whois server for getting contact details.
        """
        nhost = None
        match = re.compile('Domain Name: {}\s*.*?Whois Server: (.*?)\s'.format(query), flags=re.IGNORECASE | re.DOTALL).search(buf)
        if match:
            nhost = match.groups()[0]
            # if the whois address is domain.tld/something then
            # s.connect((hostname, 43)) does not work
            if nhost.count('/') > 0:
                nhost = None
        elif hostname == NICClient.ANICHOST:
            for nichost in NICClient.ip_whois:
                if buf.find(nichost) != -1:
                    nhost = nichost
                    break
        return nhost

    def whois(self, query, hostname, flags, many_results=False):
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specifc whois server and do a lookup
        there for contact details
        """
        response = b''
        if "SOCKS" in os.environ:
            try:
                import socks
            except ImportError as e:
                print("You need to install the Python socks module. Install PIP (https://bootstrap.pypa.io/get-pip.py) and then 'pip install PySocks'")
                raise e
            socks_user, socks_password = None, None
            if "@" in os.environ["SOCKS"]:
                creds, proxy = os.environ["SOCKS"].split("@")
                socks_user, socks_password = creds.split(":")
            else:
                proxy = os.environ["SOCKS"]
            socksproxy, port = proxy.split(":")
            socks_proto = socket.AF_INET
            if socket.AF_INET6 in [sock[0] for sock in socket.getaddrinfo(socksproxy, port)]:
                socks_proto=socket.AF_INET6
            s = socks.socksocket(socks_proto)
            s.set_proxy(socks.SOCKS5, socksproxy, int(port), True, socks_user, socks_password)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        try: # socket.connect in a try, in order to allow things like looping whois on different domains without stopping on timeouts: https://stackoverflow.com/questions/25447803/python-socket-connection-exception
            s.connect((hostname, 43))
            try:
                query = query.decode('utf-8')
            except UnicodeEncodeError:
                pass  # Already Unicode (python2's error)
            except AttributeError:
                pass  # Already Unicode (python3's error)

            if hostname == NICClient.DENICHOST:
                query_bytes = "-T dn,ace -C UTF-8 " + query
            elif hostname == NICClient.DK_HOST:
                query_bytes = " --show-handles " + query
            elif hostname.endswith(NICClient.QNICHOST_TAIL) and many_results:
                query_bytes = '=' + query
            else:
                query_bytes = query
            s.send(bytes(query_bytes, 'utf-8') + b"\r\n")
            # recv returns bytes
            while True:
                d = s.recv(4096)
                response += d
                if not d:
                    break
            s.close()

            nhost = None
            response = response.decode('utf-8', 'replace')
            if 'with "=xxx"' in response:
                return self.whois(query, hostname, flags, True)
            if flags & NICClient.WHOIS_RECURSE and nhost is None:
                nhost = self.findwhois_server(response, hostname, query)
            if nhost is not None:
                response += self.whois(query, nhost, 0)
        except socket.error as exc: # 'response' is assigned a value (also a str) even on socket timeout
            logging.debug("Error trying to connect to socket: closing socket") 
            s.close()
            response = "Socket not responding"   
        return response

    def choose_server(self, domain):
        """Choose initial lookup NIC host"""
        try:
            domain = domain.encode('idna').decode('utf-8')
        except TypeError:
            domain = domain.decode('utf-8').encode('idna').decode('utf-8')
        except AttributeError:
            domain = domain.decode('utf-8').encode('idna').decode('utf-8')
        if domain.endswith("-NORID"):
            return NICClient.NORIDHOST
        if domain.endswith("id"):
            return NICClient.PANDIHOST
        if domain.endswith("hr"):
            return NICClient.HR_HOST

        domain = domain.split('.')
        if len(domain) < 2:
            return None
        tld = domain[-1]
        if tld[0].isdigit():
            return NICClient.ANICHOST
        elif tld == 'ai':
            return NICClient.AI_HOST
        elif tld == 'app':
            return NICClient.APP_HOST
        elif tld == 'dev':
            return NICClient.DEV_HOST
        elif tld == 'games':
            return NICClient.GAMES_HOST
        elif tld == 'page':
            return NICClient.PAGE_HOST
        elif tld == 'money':
            return NICClient.MONEY_HOST
        elif tld == 'online':
            return NICClient.ONLINE_HOST
        elif tld == 'cl':
            return NICClient.CL_HOST
        elif tld == 'ar':
            return NICClient.AR_HOST
        elif tld == 'by':
            return NICClient.BY_HOST
        elif tld == 'cr':
            return NICClient.CR_HOST
        elif tld == 'ca':
            return NICClient.CA_HOST
        elif tld == 'do':
            return NICClient.DO_HOST
        elif tld == 'de':
            return NICClient.DE_HOST
        elif tld == 'hk':
            return NICClient.HK_HOST
        elif tld == 'hn':
            return NICClient.HN_HOST
        elif tld == 'jobs':
            return NICClient.JOBS_HOST
        elif tld == 'lat':
            return NICClient.LAT_HOST
        elif tld == 'li':
            return NICClient.LI_HOST
        elif tld == 'mx':
            return NICClient.MX_HOST
        elif tld == 'pe':
            return NICClient.PE_HOST
        elif tld == 'ist':
            return NICClient.IST_HOST
        elif tld == 'kz':
            return NICClient.KZ_HOST
        elif tld == 'abogado':
            return NICClient.ABOGADO_HOST
        elif tld == 'accountant':
            return NICClient.ACCOUNTANT_HOST
        elif tld == 'aero':
            return NICClient.AERO_HOST
        elif tld == 'ag':
            return NICClient.AG_HOST
        elif tld == 'ai':
            return NICClient.AI_HOST
        elif tld == 'allfinanz':
            return NICClient.ALLFINANZ_HOST
        elif tld == 'alsace':
            return NICClient.ALSACE_HOST
        elif tld == 'am':
            return NICClient.AM_HOST
        elif tld == 'amsterdam':
            return NICClient.AMSTERDAM_HOST
        elif tld == 'aquarelle':
            return NICClient.AQUARELLE_HOST
        elif tld == 'as':
            return NICClient.AS_HOST
        elif tld == 'asia':
            return NICClient.ASIA_HOST
        elif tld == 'au':
            return NICClient.AU_HOST
        elif tld == 'aw':
            return NICClient.AW_HOST
        elif tld == 'ax':
            return NICClient.AX_HOST
        elif tld == 'bank':
            return NICClient.BANK_HOST
        elif tld == 'bar':
            return NICClient.BAR_HOST
        elif tld == 'barclaycard':
            return NICClient.BARCLAYCARD_HOST
        elif tld == 'barclays':
            return NICClient.BARCLAYS_HOST
        elif tld == 'bayern':
            return NICClient.BAYERN_HOST
        elif tld == 'beer':
            return NICClient.BEER_HOST
        elif tld == 'berlin':
            return NICClient.BERLIN_HOST
        elif tld == 'bi':
            return NICClient.BI_HOST
        elif tld == 'bid':
            return NICClient.BID_HOST
        elif tld == 'bio':
            return NICClient.BIO_HOST
        elif tld == 'bmw':
            return NICClient.BMW_HOST
        elif tld == 'biz':
            return NICClient.BIZ_HOST
        elif tld == 'bj':
            return NICClient.BJ_HOST
        elif tld == 'blog':
            return NICClient.BLOG_HOST
        elif tld == 'brussels':
            return NICClient.BRUSSELS_HOST
        elif tld == 'budapest':
            return NICClient.BUDAPEST_HOST
        elif tld == 'build':
            return NICClient.BUILD_HOST
        elif tld == 'buzz':
            return NICClient.BUZZ_HOST
        elif tld == 'bw':
            return NICClient.BW_HOST
        elif tld == 'by':
            return NICClient.BY_HOST
        elif tld == 'bzh':
            return NICClient.BZH_HOST
        elif tld == 'ca':
            return NICClient.CA_HOST
        elif tld == 'cam':
            return NICClient.CAM_HOST
        elif tld == 'cancerresearch':
            return NICClient.CANCERRESEARCH_HOST
        elif tld == 'capetown':
            return NICClient.CAPETOWN_HOST
        elif tld == 'career':
            return NICClient.CAREER_HOST
        elif tld == 'casa':
            return NICClient.CASA_HOST
        elif tld == 'cat':
            return NICClient.CAT_HOST
        elif tld == 'cc':
            return NICClient.CC_HOST
        elif tld == 'ch':
            return NICClient.CH_HOST
        elif tld == 'ci':
            return NICClient.CI_HOST
        elif tld == 'cl':
            return NICClient.CL_HOST
        elif tld == 'cloud':
            return NICClient.CLOUD_HOST
        elif tld == 'club':
            return NICClient.CLUB_HOST
        elif tld == 'cm':
            return NICClient.CM_HOST
        elif tld == 'cologne':
            return NICClient.COLOGNE_HOST
        elif tld == 'cooking':
            return NICClient.COOKING_HOST
        elif tld == 'coop':
            return NICClient.COOP_HOST
        elif tld == 'cricket':
            return NICClient.CRICKET_HOST
        elif tld == 'cuisinella':
            return NICClient.CUISINELLA_HOST
        elif tld == 'cx':
            return NICClient.CX_HOST
        elif tld == 'cymru':
            return NICClient.CYMRU_HOST
        elif tld == 'cz':
            return NICClient.CZ_HOST
        elif tld == 'date':
            return NICClient.DATE_HOST
        elif tld == 'de':
            return NICClient.DE_HOST
        elif tld == 'desi':
            return NICClient.DESI_HOST
        elif tld == 'dk':
            return NICClient.DK_HOST
        elif tld == 'dm':
            return NICClient.DM_HOST
        elif tld == 'do':
            return NICClient.DO_HOST
        elif tld == 'download':
            return NICClient.DOWNLOAD_HOST
        elif tld == 'durban':
            return NICClient.DURBAN_HOST
        elif tld == 'dvag':
            return NICClient.DVAG_HOST
        elif tld == 'ee':
            return NICClient.EE_HOST
        elif tld == 'eu':
            return NICClient.EU_HOST
        elif tld == 'eurovision':
            return NICClient.EUROVISION_HOST
        elif tld == 'eus':
            return NICClient.EUS_HOST
        elif tld == 'faith':
            return NICClient.FAITH_HOST
        elif tld == 'fashion':
            return NICClient.FASHION_HOST
        elif tld == 'fi':
            return NICClient.FI_HOST
        elif tld == 'film':
            return NICClient.FILM_HOST
        elif tld == 'firmdale':
            return NICClient.FIRMDALE_HOST
        elif tld == 'fishing':
            return NICClient.FISHING_HOST
        elif tld == 'fit':
            return NICClient.FIT_HOST
        elif tld == 'flsmidth':
            return NICClient.FLSMIDTH_HOST
        elif tld == 'frl':
            return NICClient.FRL_HOST
        elif tld == 'frogans':
            return NICClient.FROGANS_HOST
        elif tld == 'ga':
            return NICClient.GA_HOST
        elif tld == 'gal':
            return NICClient.GAL_HOST
        elif tld == 'games':
            return NICClient.GAMES_HOST
        elif tld == 'garden':
            return NICClient.GARDEN_HOST
        elif tld == 'gd':
            return NICClient.GD_HOST
        elif tld == 'gdn':
            return NICClient.GDN_HOST
        elif tld == 'gent':
            return NICClient.GENT_HOST
        elif tld == 'gg':
            return NICClient.GG_HOST
        elif tld == 'gl':
            return NICClient.GL_HOST
        elif tld == 'global':
            return NICClient.GLOBAL_HOST
        elif tld == 'gmx':
            return NICClient.GMX_HOST
        elif tld == 'gold':
            return NICClient.GOLD_HOST
        elif tld == 'gop':
            return NICClient.GOP_HOST
        elif tld == 'gov':
            return NICClient.GOV_HOST
        elif tld == 'gq':
            return NICClient.GQ_HOST
        elif tld == 'gy':
            return NICClient.GY_HOST
        elif tld == 'hamburg':
            return NICClient.HAMBURG_HOST
        elif tld == 'hn':
            return NICClient.HN_HOST
        elif tld == 'horse':
            return NICClient.HORSE_HOST
        elif tld == 'hr':
            return NICClient.HR_HOST
        elif tld == 'ht':
            return NICClient.HT_HOST
        elif tld == 'hu':
            return NICClient.HU_HOST
        elif tld == 'ibm':
            return NICClient.IBM_HOST
        elif tld == 'ie':
            return NICClient.IE_HOST
        elif tld == 'ifm':
            return NICClient.IFM_HOST
        elif tld == 'im':
            return NICClient.IM_HOST
        elif tld == 'int':
            return NICClient.INT_HOST
        elif tld == 'io':
            return NICClient.IO_HOST
        elif tld == 'is':
            return NICClient.IS_HOST
        elif tld == 'it':
            return NICClient.IT_HOST
        elif tld == 'java':
            return NICClient.JAVA_HOST
        elif tld == 'je':
            return NICClient.JE_HOST
        elif tld == 'jetzt':
            return NICClient.JETZT_HOST
        elif tld == 'jobs':
            return NICClient.JOBS_HOST
        elif tld == 'joburg':
            return NICClient.JOBURG_HOST
        elif tld == 'ki':
            return NICClient.KI_HOST
        elif tld == 'kiwi':
            return NICClient.KIWI_HOST
        elif tld == 'koeln':
            return NICClient.KOELN_HOST
        elif tld == 'ky':
            return NICClient.KY_HOST
        elif tld == 'la':
            return NICClient.LA_HOST
        elif tld == 'lacaixa':
            return NICClient.LACAIXA_HOST
        elif tld == 'lat':
            return NICClient.LAT_HOST
        elif tld == 'latrobe':
            return NICClient.LATROBE_HOST
        elif tld == 'leclerc':
            return NICClient.LECLERC_HOST
        elif tld == 'li':
            return NICClient.LI_HOST
        elif tld == 'live':
            return NICClient.LIVE_HOST
        elif tld == 'loan':
            return NICClient.LOAN_HOST
        elif tld == 'london':
            return NICClient.LONDON_HOST
        elif tld == 'lt':
            return NICClient.LT_HOST
        elif tld == 'lu':
            return NICClient.LU_HOST
        elif tld == 'luxe':
            return NICClient.LUXE_HOST
        elif tld == 'luxury':
            return NICClient.LUXURY_HOST
        elif tld == 'ma':
            return NICClient.MA_HOST
        elif tld == 'madrid':
            return NICClient.MADRID_HOST
        elif tld == 'mango':
            return NICClient.MANGO_HOST
        elif tld == 'md':
            return NICClient.MD_HOST
        elif tld == 'me':
            return NICClient.ME_HOST
        elif tld == 'men':
            return NICClient.MEN_HOST
        elif tld == 'menu':
            return NICClient.MENU_HOST
        elif tld == 'mg':
            return NICClient.MG_HOST
        elif tld == 'miami':
            return NICClient.MIAMI_HOST
        elif tld == 'mini':
            return NICClient.MINI_HOST
        elif tld == 'ml':
            return NICClient.ML_HOST
        elif tld == 'mo':
            return NICClient.MO_HOST
        elif tld == 'moe':
            return NICClient.MOE_HOST
        elif tld == 'monash':
            return NICClient.MONASH_HOST
        elif tld == 'moscow':
            return NICClient.MOSCOW_HOST
        elif tld == 'ms':
            return NICClient.MS_HOST
        elif tld == 'mu':
            return NICClient.MU_HOST
        elif tld == 'museum':
            return NICClient.MUSEUM_HOST
        elif tld == 'na':
            return NICClient.NA_HOST
        elif tld == 'name':
            return NICClient.NAME_HOST
        elif tld == 'nc':
            return NICClient.NC_HOST
        elif tld == 'news':
            return NICClient.NEWS_HOST
        elif tld == 'nf':
            return NICClient.NF_HOST
        elif tld == 'nl':
            return NICClient.NL_HOST
        elif tld == 'no':
            return NICClient.NO_HOST
        elif tld == 'nrw':
            return NICClient.NRW_HOST
        elif tld == 'nu':
            return NICClient.NU_HOST
        elif tld == 'nyc':
            return NICClient.NYC_HOST
        elif tld == 'one':
            return NICClient.ONE_HOST
        elif tld == 'online':
            return NICClient.ONLINE_HOST
        elif tld == 'ooo':
            return NICClient.OOO_HOST
        elif tld == 'ovh':
            return NICClient.OVH_HOST
        elif tld == 'paris':
            return NICClient.PARIS_HOST
        elif tld == 'party':
            return NICClient.PARTY_HOST
        elif tld == 'pf':
            return NICClient.PF_HOST
        elif tld == 'physio':
            return NICClient.PHYSIO_HOST
        elif tld == 'plus':
            return NICClient.PLUS_HOST
        elif tld == 'pm':
            return NICClient.PM_HOST
        elif tld == 'pohl':
            return NICClient.POHL_HOST
        elif tld == 'post':
            return NICClient.POST_HOST
        elif tld == 'qpon':
            return NICClient.QPON_HOST
        elif tld == 'quebec':
            return NICClient.QUEBEC_HOST
        elif tld == 'racing':
            return NICClient.RACING_HOST
        elif tld == 're':
            return NICClient.RE_HOST
        elif tld == 'reise':
            return NICClient.REISE_HOST
        elif tld == 'review':
            return NICClient.REVIEW_HOST
        elif tld == 'rodeo':
            return NICClient.RODEO_HOST
        elif tld == 'ruhr':
            return NICClient.RUHR_HOST
        elif tld == 'samsung':
            return NICClient.SAMSUNG_HOST
        elif tld == 'saarland':
            return NICClient.SAARLAND_HOST
        elif tld == 'sb':
            return NICClient.SB_HOST
        elif tld == 'sca':
            return NICClient.SCA_HOST
        elif tld == 'scb':
            return NICClient.SCB_HOST
        elif tld == 'schmidt':
            return NICClient.SCHMIDT_HOST
        elif tld == 'science':
            return NICClient.SCIENCE_HOST
        elif tld == 'scot':
            return NICClient.SCOT_HOST
        elif tld == 'se':
            return NICClient.SE_HOST
        elif tld == 'sh':
            return NICClient.SH_HOST
        elif tld == 'si':
            return NICClient.SI_HOST
        elif tld == 'sk':
            return NICClient.SK_HOST
        elif tld == 'sky':
            return NICClient.SKY_HOST
        elif tld == 'sm':
            return NICClient.SM_HOST
        elif tld == 'sn':
            return NICClient.SN_HOST
        elif tld == 'so':
            return NICClient.SO_HOST
        elif tld == 'spiegel':
            return NICClient.SPIEGEL_HOST
        elif tld == 'st':
            return NICClient.ST_HOST
        elif tld == 'stream':
            return NICClient.STREAM_HOST
        elif tld == 'study':
            return NICClient.STUDY_HOST
        elif tld == 'sucks':
            return NICClient.SUCKS_HOST
        elif tld == 'surf':
            return NICClient.SURF_HOST
        elif tld == 'sx':
            return NICClient.SX_HOST
        elif tld == 'sydney':
            return NICClient.SYDNEY_HOST
        elif tld == 'taipei':
            return NICClient.TAIPEI_HOST
        elif tld == 'tatar':
            return NICClient.TATAR_HOST
        elif tld == 'tc':
            return NICClient.TC_HOST
        elif tld == 'tel':
            return NICClient.TEL_HOST
        elif tld == 'tf':
            return NICClient.TF_HOST
        elif tld == 'tirol':
            return NICClient.TIROL_HOST
        elif tld == 'tk':
            return NICClient.TK_HOST
        elif tld == 'tl':
            return NICClient.TL_HOST
        elif tld == 'tm':
            return NICClient.TM_HOST
        elif tld == 'top':
            return NICClient.TOP_HOST
        elif tld == 'tr':
            return NICClient.TR_HOST
        elif tld == 'trade':
            return NICClient.TRADE_HOST
        elif tld == 'travel':
            return NICClient.TRAVEL_HOST
        elif tld == 'trust':
            return NICClient.TRUST_HOST
        elif tld == 'tui':
            return NICClient.TUI_HOST
        elif tld == 'tv':
            return NICClient.TV_HOST
        elif tld == 'co.ua':
            return NICClient.CO.UA_HOST
        elif tld == 'uno':
            return NICClient.UNO_HOST
        elif tld == 'us':
            return NICClient.US_HOST
        elif tld == 'uz':
            return NICClient.UZ_HOST
        elif tld == 'versicherung':
            return NICClient.VERSICHERUNG_HOST
        elif tld == 'vg':
            return NICClient.VG_HOST
        elif tld == 'vip':
            return NICClient.VIP_HOST
        elif tld == 'vlaanderen':
            return NICClient.VLAANDEREN_HOST
        elif tld == 'vodka':
            return NICClient.VODKA_HOST
        elif tld == 'voting':
            return NICClient.VOTING_HOST
        elif tld == 'wales':
            return NICClient.WALES_HOST
        elif tld == 'webcam':
            return NICClient.WEBCAM_HOST
        elif tld == 'wed':
            return NICClient.WED_HOST
        elif tld == 'wedding':
            return NICClient.WEDDING_HOST
        elif tld == 'wf':
            return NICClient.WF_HOST
        elif tld == 'whoswho':
            return NICClient.WHOSWHO_HOST
        elif tld == 'wien':
            return NICClient.WIEN_HOST
        elif tld == 'win':
            return NICClient.WIN_HOST
        elif tld == 'work':
            return NICClient.WORK_HOST
        elif tld == 'ws':
            return NICClient.WS_HOST
        elif tld == 'wtc':
            return NICClient.WTC_HOST
        elif tld == 'xxx':
            return NICClient.XXX_HOST
        elif tld == 'yoga':
            return NICClient.YOGA_HOST
        elif tld == 'yt':
            return NICClient.YT_HOST
        elif tld == 'zm':
            return NICClient.ZM_HOST
        else:
            return tld + NICClient.QNICHOST_TAIL

    def whois_lookup(self, options, query_arg, flags):
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records"""
        nichost = None
        # whoud happen when this function is called by other than main
        if options is None:
            options = {}

        if ('whoishost' not in options or options['whoishost'] is None) \
                and ('country' not in options or options['country'] is None):
            self.use_qnichost = True
            options['whoishost'] = NICClient.NICHOST
            if not (flags & NICClient.WHOIS_QUICK):
                flags |= NICClient.WHOIS_RECURSE

        if 'country' in options and options['country'] is not None:
            result = self.whois(
                query_arg,
                options['country'] + NICClient.QNICHOST_TAIL,
                flags
            )
        elif self.use_qnichost:
            nichost = self.choose_server(query_arg)
            if nichost is not None:
                result = self.whois(query_arg, nichost, flags)
            else:
                result = ''
        else:
            result = self.whois(query_arg, options['whoishost'], flags)
        return result


def parse_command_line(argv):
    """Options handling mostly follows the UNIX whois(1) man page, except
    long-form options can also be used.
    """
    flags = 0

    usage = "usage: %prog [options] name"

    parser = optparse.OptionParser(add_help_option=False, usage=usage)
    parser.add_option("-a", "--arin", action="store_const",
                      const=NICClient.ANICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.ANICHOST)
    parser.add_option("-A", "--apnic", action="store_const",
                      const=NICClient.PNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.PNICHOST)
    parser.add_option("-b", "--abuse", action="store_const",
                      const=NICClient.ABUSEHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.ABUSEHOST)
    parser.add_option("-c", "--country", action="store",
                      type="string", dest="country",
                      help="Lookup using country-specific NIC")
    parser.add_option("-d", "--mil", action="store_const",
                      const=NICClient.DNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.DNICHOST)
    parser.add_option("-g", "--gov", action="store_const",
                      const=NICClient.GNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.GNICHOST)
    parser.add_option("-h", "--host", action="store",
                      type="string", dest="whoishost",
                      help="Lookup using specified whois host")
    parser.add_option("-i", "--nws", action="store_const",
                      const=NICClient.INICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.INICHOST)
    parser.add_option("-I", "--iana", action="store_const",
                      const=NICClient.IANAHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.IANAHOST)
    parser.add_option("-l", "--lcanic", action="store_const",
                      const=NICClient.LNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.LNICHOST)
    parser.add_option("-m", "--ra", action="store_const",
                      const=NICClient.MNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.MNICHOST)
    parser.add_option("-p", "--port", action="store",
                      type="int", dest="port",
                      help="Lookup using specified tcp port")
    parser.add_option("-Q", "--quick", action="store_true",
                      dest="b_quicklookup",
                      help="Perform quick lookup")
    parser.add_option("-r", "--ripe", action="store_const",
                      const=NICClient.RNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.RNICHOST)
    parser.add_option("-R", "--ru", action="store_const",
                      const="ru", dest="country",
                      help="Lookup Russian NIC")
    parser.add_option("-6", "--6bone", action="store_const",
                      const=NICClient.SNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.SNICHOST)
    parser.add_option("-n", "--ina", action="store_const",
                      const=NICClient.PANDIHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.PANDIHOST)
    parser.add_option("-?", "--help", action="help")

    return parser.parse_args(argv)


if __name__ == "__main__":
    flags = 0
    nic_client = NICClient()
    options, args = parse_command_line(sys.argv)
    if options.b_quicklookup:
        flags = flags | NICClient.WHOIS_QUICK
    print(nic_client.whois_lookup(options.__dict__, args[1], flags))
