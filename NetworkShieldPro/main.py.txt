#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARP Spoofing Tespit Aracı - Spotify UI Versiyonu
Bu araç, ağda olası ARP spoofing saldırılarını tespit etmek için gerekli tüm fonksiyonları ve 
tkinter tabanlı Spotify tarzında bir grafik arayüz içerir.

Versiyon: 2.0
"""

import tkinter as tk
from ui.screens import SpotifyARPApp
from flask import Flask, render_template, jsonify

# Flask uygulaması - Replit workflow'ları için gerekli
app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({"status": "ARP Spoofing Tespit Aracı çalışıyor",
                   "message": "Bu bir tkinter masaüstü uygulamasıdır. Replit'in VNC görüntüleyicisi aracılığıyla görüntülenebilir."})

# Masaüstü uygulaması başlatma fonksiyonu
def start_desktop_app():
    # Ana uygulamayı başlat
    root = tk.Tk()
    root.title("ARP Spoofing Tespit Aracı")
    root.geometry("1000x650")
    root.minsize(800, 600)
    
    # Uygulama nesnesini oluştur
    desktop_app = SpotifyARPApp(root)
    
    # Uygulamayı başlat
    root.mainloop()

if __name__ == "__main__":
    # Masaüstü uygulamasını doğrudan başlat
    start_desktop_app()
