# استخدام بيئة خفيفة وسريعة لتشغيل سيرفر الموقع
FROM node:18-alpine

# تحديد مسار العمل
WORKDIR /app

# نسخ ملفات الحزم لتثبيت أي مكتبات مطلوبة
COPY package*.json ./
RUN npm install

# نسخ جميع ملفات الموقع (HTML, JS, وغيرها)
COPY . .

# فتح المنفذ الذي تتطلبه المنصة
EXPOSE 7860

# أمر تشغيل الموقع
CMD ["node", "server.js"]
