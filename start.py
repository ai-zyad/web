#!/usr/bin/env python3
"""
ملف تشغيل المنصة التعليمية
==========================
"""
import os
import sys

# إضافة المسار
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, init_app

if __name__ == '__main__':
    print("=" * 60)
    print("منصة تعليمية متكاملة - Flask Education Platform")
    print("=" * 60)
    print()
    print("جاري تهيئة التطبيق...")
    init_app()
    print("✓ تم تهيئة التطبيق بنجاح")
    print()
    print("بيانات الدخول الافتراضية:")
    print("  - اسم المستخدم: admin")
    print("  - كلمة المرور: admin123")
    print()
    print("الرابط: http://localhost:5000")
    print("=" * 60)
    print()
    
    # تشغيل التطبيق
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
