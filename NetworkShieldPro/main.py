#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARP Spoofing Tespit Aracı - Spotify UI Versiyonu
Bu araç, ağda olası ARP spoofing saldırılarını tespit etmek için gerekli tüm fonksiyonları ve 
tkinter tabanlı Spotify tarzında bir grafik arayüz içerir.

Versiyon: 2.0 - Windows Uyumlu
"""

import os
import sys
import tkinter as tk
from ui.screens import SpotifyARPApp

# Masaüstü uygulaması başlatma fonksiyonu
def start_desktop_app():
    try:
        print("Tkinter UI başlatılıyor...")
        
        # Ana uygulamayı başlat
        root = tk.Tk()
        root.title("ARP Spoofing Tespit Aracı")
        root.geometry("1000x650")
        root.minsize(800, 600)
        
        # Uygulama nesnesini oluştur
        desktop_app = SpotifyARPApp(root)
        
        print("Uygulama başarıyla başlatıldı!")
        
        # Uygulamayı başlat
        root.mainloop()
    except Exception as e:
        print(f"Uygulama başlatılırken hata oluştu: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Masaüstü uygulamasını doğrudan başlat
    start_desktop_app()
