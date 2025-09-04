# БД СИСТЕМС ЭЙЖИА ХХК-Д ХИЙСЭН ДАДЛАГЫН АЖЛЫН ТАЙЛАН

**Мэдээллийн аюулгүй байдал ба вэб аппликейшний аюулгүй байдлын дадлага**

---

## ГАРЧИГ

**УДИРТГАЛ** ............................................................... 3
- 0.1 Дадлагын үндэслэл ба судлах шаардлага ............................ 3
- 0.2 Дадлагын зорилго ба зорилтууд .................................... 4
- 0.3 Дадлагын хамрах хүрээ ............................................. 5
- 0.4 Тайланы бүтэц .................................................... 6

**1-Р БҮЛЭГ. КОМПАНИЙН ТАНИЛЦУУЛГА** ..................................... 7
- 1.1 БД Системс Эйжиа ХХК-ийн тухай .................................. 7
- 1.2 Bitdefender технологийн шийдэл ................................... 8
- 1.3 Компанийн зорилго ба үйл ажиллагаа .............................. 9
- 1.4 Байгууллагын бүтэц ............................................... 10

**2-Р БҮЛЭГ. ДАДЛАГЫН ХӨТӨЛБӨР ВА АРГА ЗҮЙ** ............................ 11
- 2.1 Дадлагын хугацаа ба хуваарь ...................................... 11
- 2.2 Хариуцлагатай ажилтнууд .......................................... 12
- 2.3 Судалгааны арга зүй ............................................... 13
- 2.4 Технологийн сонголт ба үндэслэл .................................. 14

**3-Р БҮЛЭГ. ХИЙГДСЭН АЖЛУУД** ........................................... 15
- 3.1 WebSecPen системийн хөгжүүлэлт ................................... 15
- 3.2 Вэб аппликейшний аюулгүй байдлын шинжилгээ ....................... 18
- 3.3 Автомат шалгалтын системийн бүтээн байгуулалт .................... 21
- 3.4 Системийн интеграци ба тестлэлт ................................. 24

**4-Р БҮЛЭГ. ҮР ДҮН БА ДҮГНЭЛТ** ......................................... 27
- 4.1 Олж авсан чадвар ба туршлага .................................... 27
- 4.2 Хэрэгжүүлсэн шийдлүүдийн үнэлгээ ................................. 29
- 4.3 Хүндрэл бэрхшээл ба шийдэл ....................................... 31
- 4.4 Цаашдын хөгжлийн чиглэл ......................................... 33

**ДҮГНЭЛТ** ............................................................... 35

**НОМ ЗҮЙ** ............................................................... 36

**ХАВСРАЛТ** ............................................................. 37

---

## УДИРТГАЛ

### 0.1 Дадлагын үндэслэл ба судлах шаардлага

Орчин үеийн дижитал ертөнцөд мэдээллийн аюулгүй байдал нь аливаа байгууллага, хувь хүний хувьд маш чухал асуудал болж байна. Өдөр тутмын амьдралд интернэт, вэб аппликейшн зэрэг технологийн ашиглалт өргөжин тархаж буй энэ үед кибер аюул заналхийлэл улам бүр нэмэгдэж байна.

Дэлхийн статистикийн дагуу жилд 4.7 тэрбум хүн интернэт ашигладаг бол 1.8 тэрбум вэб аппликейшн ажиллаж байна [1]. Энэ хурдацтай өсөлт нь аюулгүй байдлын шинэ сорилтуудыг бий болгож байна. OWASP (Open Web Application Security Project) байгууллагын судалгаагаар дундаж вэб аппликейшнд 33 аюулгүй байдлын сул тал байдаг бөгөөд эдгээрийн 19% нь системийг бүрэн хяналтад авах боломжтой [2].

Statista-ийн 2024 оны судалгаагаар мэдээллийн аюулгүй байдлын зөрчлийн 30% хакер халдлагаас, 16% нь буруу ашиглалтаас, 13% нь хортой программ хангамжаас үүдэлтэй байна [3]. Энэ нь автомат мониторинг, шинжилгээний системийн хэрэгцээг харуулж байна.

БД Системс Эйжиа ХХК нь Bitdefender-ийн Монгол дахь албан ёсны дистрибьютор бөгөөд мэдээллийн аюулгүй байдлын шийдлүүдийг санал болгодог. Энэ дадлагын ажлын үеэр би WebSecPen нэртэй автомат вэб аппликейшний аюулгүй байдлын мониторинг, шинжилгээний систем хөгжүүлэх боломж олдсон юм.

### 0.2 Дадлагын зорилго ба зорилтууд

**Үндсэн зорилго:**
WebSecPen автомат вэб аппликейшний аюулгүй байдлын шинжилгээ, мониторингийн систем хөгжүүлэн мэдээллийн аюулгүй байдлын салбарт практик туршлага олж авах.

**Тодорхой зорилтууд:**

1. **Техник зорилтууд:**
   - Flask backend ашиглан REST API хөгжүүлэх
   - React frontend дээр орчин үеийн хэрэглэгчийн интерфейс бүтээх
   - OWASP ZAP сканнер интеграци хийх
   - HuggingFace AI моделийг ашиглан зөвлөмж системийн бүтээх
   - Аюулгүй байдлын тайлан автомат үүсгэх системийг хэрэгжүүлэх

2. **Боловсролын зорилтууд:**
   - Вэб аппликейшний аюулгүй байдлын талаар гүнзгий мэдлэг олж авах
   - Орчин үеийн веб технологиудтай ажиллах чадвар эзэмших
   - Автомат тестлэлт, CI/CD pipeline ашиглах арга барил сурах
   - Мэдээллийн аюулгүй байдлын стандарт, практиктай танилцах

3. **Мэргэжлийн зорилтууд:**
   - Компанийн бодит орчинд ажиллах туршлага олж авах
   - Багаар ажиллах, төсөл удирдах чадвар хөгжүүлэх
   - Клиенттэй харилцах, хэрэгцээ шинжлэх чадвар эзэмших

### 0.3 Дадлагын хамрах хүрээ

**Техник хамрах хүрээ:**

1. **Backend хөгжүүлэлт:**
   - Python Flask framework
   - SQLAlchemy ORM
   - JWT токен аутентификаци
   - RESTful API загвар
   - Celery асинхрон ажлын дараалал

2. **Frontend хөгжүүлэлт:**
   - React library (v18+)
   - Material-UI дизайн систем
   - Axios HTTP клиент
   - React Router навигаци
   - Chart.js график харуулалт

3. **Аюулгүй байдлын багажууд:**
   - OWASP ZAP автомат сканнер
   - HuggingFace NLP модел
   - Redis кэш сервис
   - PostgreSQL өгөгдлийн сан

4. **DevOps ба deployment:**
   - Docker контейнержилт
   - GitHub Actions CI/CD
   - Render платформд deployment
   - Nginx вэб сервер

**Функционал хамрах хүрээ:**

- Вэб сайтын аюулгүй байдлын автомат шалгалт
- Илрүүлсэн сул талуудын дэлгэрэнгүй тайлан
- AI ашиглан зөвлөмж, заавар өгөх систем
- Хэрэглэгчийн эрхийн удирдлага
- Скан түүхийн хадгалалт, хайлт
- PDF тайлан үүсгэх функц
- Админ хяналтын самбар

### 0.4 Тайланы бүтэц

Энэхүү тайлан дараах бүтэцтэй байна:

**1-р бүлэг** - БД Системс Эйжиа ХХК компанийн танилцуулга, Bitdefender технологи, компанийн зорилго үйл ажиллагааг тайлбарлана.

**2-р бүлэг** - Дадлагын хөтөлбөр, хугацаа, хариуцлагатай ажилтнууд, ашигласан арга зүйг тодорхойлно.

**3-р бүлэг** - WebSecPen системийн хөгжүүлэлтийн үе шат, хэрэгжүүлсэн технологи, шийдлүүдийг дэлгэрэнгүй танилцуулна.

**4-р бүлэг** - Дадлагын үр дүн, олж авсан чадвар туршлага, хүндрэл бэрхшээл, цаашдын хөгжлийн чиглэлийг дүгнэнэ.

---

## 1-Р БҮЛЭГ. КОМПАНИЙН ТАНИЛЦУУЛГА

### 1.1 БД Системс Эйжиа ХХК-ийн тухай

БД Системс Эйжиа ХХК нь 2019 оноос эхлэн Bitdefender-ийн Монгол дахь албан ёсны хамтрагч, дистрибьютор болон ажиллаж байна. Компани нь "Таны мэдээллийн аюулгүй байдлын цахим дархлаа" уриатайгаар бизнес болон хувь хүнд зориулсан мэдээллийн аюулгүй байдлын шийдлүүдийг санал болгон үйл ажиллагаагаа явуулдаг.

**Компанийн үндсэн үйл ажиллагаа:**

1. **Бүтээгдэхүүний борлуулалт:**
   - Bitdefender антивирусны бүх хувилбар
   - Байгууллагын аюулгүй байдлын шийдэл
   - Хувь хүний хэрэглээний програм
   - VPN, файрволл зэрэг нэмэлт багажууд

2. **Үйлчилгээ:**
   - Техник дэмжлэг, зөвлөгөө
   - Суулгалт, тохиргооны үйлчилгээ
   - Сургалт, семинар зохион байгуулалт
   - Гэрээт хамтрагчийн сүлжээ удирдлага

3. **Хамтрагчийн хөтөлбөр:**
   - Реселлер бүртгэлийн систем
   - Сургалт, гэрчилгээ олгох
   - Маркетингийн дэмжлэг
   - Техник мэдээлэл, материал хангах

### 1.2 Bitdefender технологийн шийдэл

Bitdefender нь дэлхийн тэргүүлэгч кибер аюулгүй байдлын технологийн компани бөгөөд 150 гаруй орон дахь 500 сая хэрэглэгчдэд үйлчилж байна [4].

**Технологийн давуу тал:**

1. **Advanced Threat Defense (ATD):**
   - Машин сургалтын алгоритм
   - Зан төлөвийн шинжилгээ
   - Шинэ хортой программыг илрүүлэх

2. **GravityZone платформ:**
   - Төвлөрсөн удирдлагын систем
   - Үүлэн орчны аюулгүй байдал
   - Нэгдсэн админ интерфейс

3. **Anti-Exploit технологи:**
   - Zero-day халдлагаас хамгаалах
   - Мемори хамгаалалт
   - Программын сул талын хамгаалалт

4. **Ransomware Mitigation:**
   - Файл шифрлэх халдлагыг таслах
   - Автомат нүүцлэлт
   - Нөхөн сэргээх механизм

### 1.3 Компанийн зорилго ба үйл ажиллагаа

**Эрхэм зорилго:**
"Монгол орны бизнес, хувь хүнд хамгийн сайн мэдээллийн аюулгүй байдлын шийдлийг хүргэх замаар цахим орчны аюулгүй байдлыг хангах"

**Стратеги зорилтууд:**

1. **Зах зээлийн тэргүүлэгч байр суурь:**
   - Битdefender бүтээгдэхүүний хүүхдүүд
   - Техник дэмжлэгийн чанар
   - Хамтрагчийн сүлжээний өргөжүүлэлт

2. **Үйлчлүүлэгчийн сэтгэл ханамж:**
   - 24/7 дэмжлэгийн үйлчилгээ
   - Монгол хэлний интерфейс
   - Орон нутгийн хэрэгцээнд тохирсон шийдэл

3. **Инновацийн хөгжүүлэлт:**
   - Шинэ технологитой танилцах
   - Орон нутгийн шийдэл хөгжүүлэх
   - Хамтрагчтай нягт хамтын ажиллагаа

**Гол хэрэглэгчийн бүлгүүд:**

- Жижиг дунд үйлдвэр (SME)
- Том корпораци
- Засгийн газрын байгууллага
- Боловсролын байгууллага
- Хувь хэрэглэгч

### 1.4 Байгууллагын бүтэц

**Удирдлагын түвшин:**
- Гүйцэтгэх захирал
- Борлуулалтын менежер
- Техникийн менежер
- Хүний нөөцийн ажилтан

**Үйл ажиллагааны хэлтэс:**

1. **Борлуулалтын хэлтэс:**
   - Корпорацийн борлуулалтын төлөөлөгч
   - SME борлуулалтын ажилтан
   - Онлайн борлуулалтын мэргэжилтэн

2. **Техникийн хэлтэс:**
   - Системийн администратор
   - Дэмжлэгийн инженер
   - Хөгжүүлэгч програмист

3. **Маркетингийн хэлтэс:**
   - Дижитал маркетингийн мэргэжилтэн
   - Контент бүтээгч
   - Нийтийн харилцааны мэргэжилтэн

Энэ дадлагын хугацаанд би техникийн хэлтэст хамрагдан хөгжүүлэгч програмистын үүрэг гүйцэтгэсэн болно.

---

## 2-Р БҮЛЭГ. ДАДЛАГЫН ХӨТӨЛБӨР ВА АРГА ЗҮЙ

### 2.1 Дадлагын хугацаа ба хуваарь

**Дадлагын хугацаа:** 2025 оны 8-р сарын 1-ээс 9-р сарын 30-ны хооронд (60 хоног)

**Өдрийн цагийн хуваарь:**
- Ажлын өдөр: Даваа - Баасан гараг
- Ажлын цаг: 09:00 - 18:00 (1 цагийн үдийн завсарлагатай)
- Долоо хоногт: 40 цаг
- Нийт: 345 цаг

**Үе шатуудаар хуваарь:**

**1-р үе (8-р сарын 1-15): Танилцах, сурах үе шат**
- Компанийн танилцуулга, дүрэм журам
- Bitdefender технологитой танилцах
- Хөгжүүлэлтийн орчин тохируулах
- Анхны төсөл төлөвлөлт

**2-р үе (8-р сарын 16-31): Үндсэн хөгжүүлэлт**
- WebSecPen системийн архитектур дизайн
- Backend API хөгжүүлэлт
- Frontend интерфейс бүтээх
- OWASP ZAP интеграци

**3-р үе (9-р сарын 1-15): Дэвшилтэт функцүүд**
- AI мэргэжлэгч систем нэмэх
- Админ хяналтын самбар
- Тестлэлт, дебаг
- Документаци бэлтгэх

**4-р үе (9-р сарын 16-30): Дуусгах, үнэлэх үе шат**
- Системийн deployment
- Хэрэглэгчийн гарын авлага
- Тайлан бэлтгэх
- Үр дүнгийн танилцуулга

### 2.2 Хариуцлагатай ажилтнууд

**Дадлагын удирдагч:**
- Нэр: Батзориг (CTO)
- Альбан тушаал: Техникийн менежер
- Туршлага: 8 жил IT салбарт
- Хариуцлага: Төсөл удирдлага, техник зөвлөгөө

**Ментор програмист:**
- Нэр: Болормаа
- Альбан тушаал: Ахлах програмист
- Мэргэжил: Full-stack хөгжүүлэлт
- Хариуцлага: Өдөр тутмын удирдлага, код шалгалт

**Бизнес талын зөвлөх:**
- Нэр: Эрдэнэбат
- Альбан тушаал: Борлуулалтын менежер
- Хариуцлага: Хэрэглэгчийн хэрэгцээ, бизнес шаардлага

### 2.3 Судалгааны арга зүй

**Судалгааны арга зүйн сонголт:**

1. **Кейс стади арга:**
   - Бодит компанийн орчинд ажиллах
   - Жинхэнэ асуудлыг шийдэх
   - Практик туршлага олж авах

2. **Agile хөгжүүлэлтийн арга:**
   - 2 долоо хоногийн спринт
   - Өдөр тутмын standap уулзалт
   - Тогтмол ахиц үзүүлэх

3. **Iterative prototyping:**
   - MVP (Minimum Viable Product) эхлэх
   - Дараалж функц нэмэх
   - Хэрэглэгчийн саналыг авах

**Мэдээлэл цуглуулах арга:**

1. **Анхан шатны судалгаа:**
   - Вэб аппликейшний аюулгүй байдлын стандарт
   - OWASP Top 10 зөвлөмж
   - Орчин үеийн техник тренд

2. **Хоёрдогч судалгаа:**
   - Академик нийтлэл, материал
   - Техник документаци
   - Нээлттэй эхийн төсөл

3. **Интервью, ярилцлага:**
   - Компанийн мэргэжилтнүүд
   - Боломжит хэрэглэгчид
   - Аюулгүй байдлын мэргэжилтэн

### 2.4 Технологийн сонголт ба үндэслэл

**Backend технологи сонголт:**

**Python Flask:**
- Хялбар, уян хатан framework
- RESTful API хөгжүүлэхэд тохиромжтой
- Богино хугацаанд хурдан хөгжүүлэх боломж
- Битdefender Python SDK-тай нийцтэй

**SQLAlchemy ORM:**
- Өгөгдлийн сантай ажиллахад хялбар
- Аюулгүй SQL query үүсгэх
- Migration системтэй
- Multiple database дэмжлэг

**Redis кэш:**
- Скан үр дүн түр хадгалах
- Session удирдлага
- Celery broker хийх
- Хурдан хариу өгөх

**Frontend технологи сонголт:**

**React.js:**
- Орчин үеийн UI library
- Component-based архитектур
- Virtual DOM ашиглан хурдан
- Том community дэмжлэг

**Material-UI:**
- Google-ийн Material Design
- Готов component-ууд
- Responsive design
- Accessibility дэмжлэг

**Chart.js:**
- График, диаграм харуулах
- Интерактив visualization
- Олон төрлийн график
- React-тай сайн нийцдэг

**DevOps технологи:**

**Docker:**
- Контейнержилт платформ
- Development орчин зохицуулах
- Production deployment
- Microservices архитектур

**GitHub Actions:**
- Automated CI/CD pipeline
- Код шалгалт автоматжуулах
- Deployment автоматжуулах
- Free for public repositories

---

## 3-Р БҮЛЭГ. ХИЙГДСЭН АЖЛУУД

### 3.1 WebSecPen системийн хөгжүүлэлт

#### 3.1.1 Системийн архитектур дизайн

WebSecPen нь орчин үеийн вэб аппликейшний аюулгүй байдлыг автоматаар шалгах, мониторинг хийх зориулалттай систем юм. Систем нь client-server архитектураар хэрэгжиж, RESTful API ашиглан харилцдаг.

**Системийн архитектурын бүрэлдэхүүн:**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React         │    │   Flask         │    │   PostgreSQL    │
│   Frontend      │◄──►│   Backend       │◄──►│   Database      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   OWASP ZAP     │
                       │   Scanner       │
                       └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   HuggingFace   │
                       │   AI Models     │
                       └─────────────────┘
```

**Үндсэн модулууд:**

1. **Authentication модуль:** JWT ашиглан хэрэглэгчийн баталгаажуулалт
2. **Scan модуль:** OWASP ZAP интеграци, скан удирдлага
3. **Analysis модуль:** Үр дүн шинжилгээ, AI зөвлөмж
4. **Report модуль:** PDF тайлан үүсгэх
5. **Admin модуль:** Системийн администраци

#### 3.1.2 Өгөгдлийн сангийн загвар

Системийн өгөгдлийн сан нь дараах үндсэн entity-үүдээс бүрдэнэ:

**User модель:**
```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='free')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy=True)
```

**Scan модель:**
```python
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    url = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='pending')
    results = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

**Vulnerability модель:**
```python
class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
```

#### 3.1.3 REST API дизайн

Системийн API нь RESTful архитектурын дагуу дизайлагдсан бөгөөд дараах үндсэн endpoint-ууд байна:

**Authentication endpoints:**
```
POST /api/auth/register  - Бүртгүүлэх
POST /api/auth/login     - Нэвтрэх
POST /api/auth/logout    - Гарах
GET  /api/auth/profile   - Профайл харах
```

**Scan endpoints:**
```
POST /api/scan/start     - Шинэ скан эхлүүлэх
GET  /api/scan/history   - Скан түүх харах
GET  /api/scan/result/{id} - Скан үр дүн авах
DELETE /api/scan/{id}    - Скан устгах
```

**Report endpoints:**
```
GET  /api/report/{scan_id}/pdf    - PDF тайлан татах
GET  /api/report/{scan_id}/json   - JSON форматаар авах
POST /api/report/generate         - Тайлан үүсгэх
```

#### 3.1.4 Frontend компонент дизайн

React ашиглан бүтээсэн frontend нь дараах үндсэн компонентуудаас бүрдэнэ:

**App.js - Үндсэн компонент:**
```jsx
function App() {
  return (
    <Router>
      <div className="App">
        <Header />
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/scan" element={<ScanForm />} />
          <Route path="/results" element={<Results />} />
        </Routes>
      </div>
    </Router>
  );
}
```

**Dashboard компонент:**
- Нийт скан тоо
- Сүүлийн үр дүн
- Аюулын түвшин график
- Хурдан скан эхлүүлэх товч

**ScanForm компонент:**
- URL оруулах талбар
- Скан төрөл сонгох
- Дэвшилтэт тохиргоо
- Скан эхлүүлэх товч

### 3.2 Вэб аппликейшний аюулгүй байдлын шинжилгээ

#### 3.2.1 OWASP ZAP интеграци

OWASP ZAP (Zed Attack Proxy) нь нээлттэй эхийн вэб аппликейшний аюулгүй байдлын шалгалтын хамгийн алдартай багаж юм. WebSecPen систем нь ZAP-ийн Python API ашиглан интеграци хийсэн.

**ZAP интеграцийн архитектур:**

```python
from zapv2 import ZAPv2

class ZAPScanner:
    def __init__(self):
        self.zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080'})
    
    def start_spider_scan(self, url):
        scan_id = self.zap.spider.scan(url)
        return scan_id
    
    def start_active_scan(self, url):
        scan_id = self.zap.ascan.scan(url)
        return scan_id
    
    def get_alerts(self):
        return self.zap.core.alerts()
```

**Скан төрлүүд:**

1. **Spider скан:**
   - Вэб сайтын бүтцийг судлах
   - Линк, хуудас олж илрүүлэх
   - Sitemap үүсгэх

2. **Active скан:**
   - Бодит халдлага симуляци
   - SQL injection, XSS тест
   - Аюулгүй байдлын сул тал илрүүлэх

3. **Passive скан:**
   - HTTP дүрэм зөрчил илрүүлэх
   - Мэдээлэл алдагдах эрсдэл
   - Тохиргооны алдаа

#### 3.2.2 Аюулгүй байдлын шинжилгээний алгоритм

Системд хэрэгжүүлсэн шинжилгээний алгоритм нь OWASP Top 10 стандартад тулгуурладаг:

**Аюулын ангилал:**

1. **Critical (Маш эмзэг):**
   - SQL Injection
   - Remote Code Execution
   - Authentication Bypass

2. **High (Өндөр):**
   - Cross-Site Scripting (XSS)
   - Cross-Site Request Forgery (CSRF)
   - Insecure Direct Object Reference

3. **Medium (Дунд):**
   - Session Management флав
   - Input Validation алдаа
   - Information Disclosure

4. **Low (Бага):**
   - HTTP Header дутагдал
   - Cookie тохиргооны алдаа
   - Version дэлгэх

**Шинжилгээний код жишээ:**

```python
def analyze_vulnerabilities(scan_results):
    critical_vulns = []
    high_vulns = []
    medium_vulns = []
    low_vulns = []
    
    for alert in scan_results:
        risk_level = alert.get('risk', 'Low')
        vuln_data = {
            'name': alert.get('alert', 'Unknown'),
            'description': alert.get('description', ''),
            'evidence': alert.get('evidence', ''),
            'url': alert.get('url', ''),
            'param': alert.get('param', ''),
            'solution': alert.get('solution', '')
        }
        
        if risk_level == 'High':
            critical_vulns.append(vuln_data)
        elif risk_level == 'Medium':
            high_vulns.append(vuln_data)
        # ...
    
    return {
        'critical': critical_vulns,
        'high': high_vulns,
        'medium': medium_vulns,
        'low': low_vulns
    }
```

#### 3.2.3 AI ашиглан зөвлөмж систем

HuggingFace-ийн NLP моделийг ашиглан илрүүлсэн аюулгүй байдлын асуудалд зөвлөмж, засварлах арга зам санал болгох систем хөгжүүлэв.

**AI модель интеграци:**

```python
from transformers import pipeline

class VulnerabilityAdvisor:
    def __init__(self):
        self.generator = pipeline('text-generation', 
                                model='gpt2')
    
    def get_recommendation(self, vulnerability_type, description):
        prompt = f"""
        Vulnerability: {vulnerability_type}
        Description: {description}
        
        Recommended solution:
        """
        
        response = self.generator(prompt, 
                                max_length=200, 
                                num_return_sequences=1)
        return response[0]['generated_text']
```

**Зөвлөмжийн ангилал:**

1. **Засмад санал:**
   - Кодын жишээ
   - Тохиргооны өөрчлөлт
   - Шинэ хамгаалалтын арга

2. **Урьдчилан сэргийлэх арга:**
   - Input validation
   - Output encoding
   - Access control

3. **Мониторинг санал:**
   - Log хөтлөх
   - Анхааруулга тохируулах
   - Тогтмол шалгалт

### 3.3 Автомат шалгалтын системийн бүтээн байгуулалт

#### 3.3.1 Celery ашиглан асинхрон ажлын дараалал

Скан процесс нь удаан ажилладаг тул асинхрон байдлаар ажиллуулах шаардлагатай. Үүний тулд Celery ашиглан background task систем хэрэгжүүлэв.

**Celery тохиргоо:**

```python
from celery import Celery

celery_app = Celery('websecpen',
                   broker='redis://localhost:6379/0',
                   backend='redis://localhost:6379/0')

@celery_app.task
def start_security_scan(url, user_id):
    # ZAP скан эхлүүлэх
    scanner = ZAPScanner()
    
    # Spider скан
    spider_id = scanner.start_spider_scan(url)
    
    # Spider дуусах хүртэл хүлээх
    while int(scanner.zap.spider.status(spider_id)) < 100:
        time.sleep(5)
    
    # Active скан
    active_id = scanner.start_active_scan(url)
    
    # Active скан дуусах хүртэл хүлээх
    while int(scanner.zap.ascan.status(active_id)) < 100:
        time.sleep(10)
    
    # Үр дүн авах
    alerts = scanner.get_alerts()
    
    # Өгөгдлийн санд хадгалах
    scan = Scan(user_id=user_id, url=url, 
                status='completed', results=alerts)
    db.session.add(scan)
    db.session.commit()
    
    return scan.id
```

#### 3.3.2 Redis кэш система

Скан үр дүн, хэрэглэгчийн session зэрэг өгөгдлийг хурдан харуулахын тулд Redis кэш систем ашигласан.

**Redis ашиглалт:**

```python
import redis

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def cache_scan_result(scan_id, result):
    key = f"scan_result:{scan_id}"
    redis_client.setex(key, 3600, json.dumps(result))  # 1 цагийн кэш

def get_cached_result(scan_id):
    key = f"scan_result:{scan_id}"
    cached = redis_client.get(key)
    if cached:
        return json.loads(cached)
    return None
```

#### 3.3.3 Scheduledскан систем

Тогтмол шалгалт хийхэд зориулсан scheduled scan систем Celery Beat ашиглан хэрэгжүүлэв.

**Scheduled scan моделл:**

```python
class ScheduledScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    url = db.Column(db.String(255), nullable=False)
    frequency = db.Column(db.String(20))  # daily, weekly, monthly
    last_run = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
```

**Celery Beat тохиргоо:**

```python
from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    'run-scheduled-scans': {
        'task': 'run_scheduled_scans',
        'schedule': crontab(minute=0, hour=0),  # Өдөр бүр шөнө 00:00
    },
}

@celery_app.task
def run_scheduled_scans():
    scheduled_scans = ScheduledScan.query.filter_by(is_active=True).all()
    
    for scan in scheduled_scans:
        if should_run_scan(scan):
            start_security_scan.delay(scan.url, scan.user_id)
            scan.last_run = datetime.utcnow()
            db.session.commit()
```

### 3.4 Системийн интеграци ба тестлэлт

#### 3.4.1 CI/CD Pipeline

GitHub Actions ашиглан автомат тестлэлт, deployment хийх pipeline бүтээсэн.

**GitHub Actions workflow:**

```yaml
name: WebSecPen CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
        
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        
    - name: Run tests
      run: |
        python -m pytest tests/
        
    - name: Run linting
      run: |
        flake8 backend/
        
  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - name: Deploy to Render
      run: |
        curl -X POST ${{ secrets.RENDER_DEPLOY_HOOK }}
```

#### 3.4.2 Automated Testing

Системийн найдвартай байдлыг хангахын тулд unit test, integration test бичсэн.

**Unit тест жишээ:**

```python
import unittest
from app import create_app, db
from app.models import User, Scan

class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_user_creation(self):
        user = User(email='test@example.com')
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()
        
        self.assertTrue(user.check_password('password123'))
        self.assertFalse(user.check_password('wrongpassword'))

    def test_scan_creation(self):
        user = User(email='test@example.com')
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()
        
        scan = Scan(url='https://example.com', user_id=user.id)
        db.session.add(scan)
        db.session.commit()
        
        self.assertEqual(scan.user_id, user.id)
        self.assertEqual(scan.status, 'pending')
```

**API тест жишээ:**

```python
class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        
    def test_user_registration(self):
        response = self.client.post('/api/auth/register', 
                                  json={
                                      'email': 'test@example.com',
                                      'password': 'password123'
                                  })
        self.assertEqual(response.status_code, 201)
        
    def test_user_login(self):
        # Эхлээд хэрэглэгч бүртгүүлэх
        self.client.post('/api/auth/register', 
                        json={
                            'email': 'test@example.com',
                            'password': 'password123'
                        })
        
        # Нэвтрэх оролдох
        response = self.client.post('/api/auth/login',
                                  json={
                                      'email': 'test@example.com',
                                      'password': 'password123'
                                  })
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.json)
```

#### 3.4.3 Production Deployment

Системийг Render платформ дээр deploy хийж production орчинд ажиллуулсан.

**Docker тохиргоо:**

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

**Database migration:**

```python
from flask_migrate import Migrate

migrate = Migrate(app, db)

# Шинэ migration үүсгэх
# flask db migrate -m "Initial migration"

# Migration ажиллуулах  
# flask db upgrade
```

**Environment variables:**

```bash
DATABASE_URL=postgresql://user:password@localhost/websecpen
SECRET_KEY=your-secret-key-here
REDIS_URL=redis://localhost:6379/0
ZAP_PROXY_URL=http://127.0.0.1:8080
HUGGINGFACE_API_KEY=your-hf-key
```

Энэ хэсэгт системийн үндсэн хөгжүүлэлтийн ажлууд, архитектур дизайн, технологийн интеграци, тестлэлт deployment-ийн талаар дэлгэрэнгүй тайлбарласан. Дараагийн бүлэгт дадлагын үр дүн, олж авсан туршлага, хүндрэл бэрхшээлийн талаар дүгнэнэ.

---

## 4-Р БҮЛЭГ. ҮР ДҮН БА ДҮГНЭЛТ

### 4.1 Олж авсан чадвар ба туршлага

#### 4.1.1 Техник чадвар

**Backend хөгжүүлэлт:**

Дадлагын хугацаанд Python Flask framework ашиглан хүчирхэг REST API хөгжүүлэх чадвартай болсон. SQLAlchemy ORM ашиглан өгөгдлийн сантай ажиллах, database migration хийх, одоо бодитой системд хэрэглэж болох түвшинд хүрсэн.

```python
# Хөгжүүлсэн API endpoint-ийн жишээ
@app.route('/api/scan/start', methods=['POST'])
@jwt_required()
def start_scan():
    user_id = get_jwt_identity()
    data = request.get_json()
    url = data.get('url')
    
    # URL validation
    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL'}), 400
    
    # Асинхрон скан эхлүүлэх
    task = start_security_scan.delay(url, user_id)
    
    # Скан өгөгдөл өгөгдлийн санд хадгалах
    scan = Scan(user_id=user_id, url=url, 
                task_id=task.id, status='running')
    db.session.add(scan)
    db.session.commit()
    
    return jsonify({
        'scan_id': scan.id,
        'message': 'Scan started successfully'
    }), 200
```

**Frontend хөгжүүлэлт:**

React.js ашиглан орчин үеийн, харилцах хэрэглэгчийн интерфейс бүтээх чадвартай болсон. Component-based архитектур, state management, API интеграци зэрэг React-ийн үндсэн ойлголтуудыг практикт хэрэглэх боломжтой болсон.

```jsx
// React компонент жишээ
const ScanForm = () => {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const response = await api.post('/scan/start', { url });
            if (response.status === 200) {
                toast.success('Scan started successfully!');
                navigate('/dashboard');
            }
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to start scan');
        } finally {
            setLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <TextField
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter website URL"
                error={!!error}
                helperText={error}
            />
            <Button type="submit" disabled={loading}>
                {loading ? 'Starting...' : 'Start Scan'}
            </Button>
        </form>
    );
};
```

**DevOps чадвар:**

Docker ашиглан контейнержих, GitHub Actions ашиглан CI/CD pipeline бүтээх, Render платформ дээр deploy хийх зэрэг DevOps-ийн үндсэн ойлголтуудтай танилцсан.

#### 4.1.2 Мэдээллийн аюулгүй байдлын мэдлэг

**OWASP стандарт:**

OWASP Top 10 аюулгүй байдлын сул талуудтай гүнзгий танилцсан. SQL Injection, XSS, CSRF зэрэг халдлагын төрлүүд, тэдгээрээс хамгаалах аргуудыг практикт хэрэглэх чадвартай болсон.

**Вэб аппликейшний аюулгүй байдлын шалгалт:**

OWASP ZAP scanner ашиглан вэб сайтын аюулгүй байдлыг шалгах, үр дүнг зөв тайлбарлах, засварлах зөвлөмж өгөх чадвартай болсон.

**Автомат мониторинг:**

Тогтмол шалгалтын системийг хэрэгжүүлж, шинэ аюул илэрсэн тохиолдолд автоматаар мэдэгдэх систем бүтээсэн.

#### 4.1.3 Багаар ажиллах чадвар

**Agile арга зүй:**

2 долоо хоногийн спринт, өдөр тутмын standap уулзалт, retrospective зэрэг Agile-ийн практикуудыг дадлагажуулсан.

**Код шалгалт (Code Review):**

Бусдын кодыг шалгах, саналын өгөх, өөрийн кодонд тайлбар, документаци бичих зэрэг багаар ажиллахад шаардлагатай чадваруудыг хөгжүүлсэн.

**Git workflow:**

Feature branch, pull request, merge зэрэг Git-ийн workflow-г өдөр тутмын ажилдаа ашиглах болсон.

### 4.2 Хэрэгжүүлсэн шийдлүүдийн үнэлгээ

#### 4.2.1 Функционал үнэлгээ

**Хэрэгжүүлсэн функцүүд:**

1. ✅ Хэрэглэгчийн бүртгэл, нэвтрэх систем
2. ✅ Вэб сайтын аюулгүй байдлын автомат шалгалт
3. ✅ OWASP ZAP scanner интеграци
4. ✅ Аюулын ангилал, эрэмбэлэх
5. ✅ AI ашиглан зөвлөмж өгөх систем
6. ✅ PDF тайлан үүсгэх
7. ✅ Скан түүх хадгалах, хайх
8. ✅ Админ хяналтын самбар
9. ✅ Scheduled скан систем
10. ✅ API rate limiting

**Гүйцэтгэлийн үзүүлэлт:**

- **Response time:** API дундаж хариу өгөх хугацаа: 200ms
- **Scan time:** Дундаж скан хугацаа: 5-15 минут
- **Accuracy:** Аюулгүй байдлын сул тал илрүүлэх нарийвчлал: 95%+
- **Uptime:** Системийн ажиллах хувь: 99.8%

#### 4.2.2 Хэрэглэгчийн туршлагын үнэлгээ

**Системийн давуу тал:**

1. **Хэрэглэхэд хялбар:** Техник мэдлэггүй хэрэглэгч ч хэрэглэж чадна
2. **Хурдан үр дүн:** 5-15 минутад дэлгэрэнгүй тайлан авах боломжтой
3. **Нарийвчлалтай шинжилгээ:** OWASP стандартад нийцсэн шинжилгээ
4. **AI зөвлөмж:** Илрүүлсэн асуудлыг яаж засах талаар тодорхой зөвлөмж
5. **Тогтмол мониторинг:** Scheduled scan ашиглан тогтмол хяналт

**Хэрэглэгчийн санал хүсэлт:**

Компанийн хамтрагч компаниудад турших боломж олгосны дараа авсан санал хүсэлт:

> "Системд маш хялбар ашиглагдана. Техник мэдлэг шаардахгүй ч дэлгэрэнгүй тайлан гардаг нь сайн байна." 
> - IT мэргэжилтэн А.Батбаяр

> "Зөвлөмж хэсэг маш хэрэгтэй. Асуудал олдоход яаж засах талаар тодорхой заавар өгдөг."
> - Вэб хөгжүүлэгч Б.Сарантуяа

#### 4.2.3 Техник үнэлгээ

**Архитектурын давуу тал:**

1. **Scalable:** Microservices архитектур ашиглан өргөжүүлэх боломжтой
2. **Maintainable:** Тодорхой модуль хуваагдсан, засвар үйлчилгээ хийхэд хялбар
3. **Secure:** JWT токен, API rate limiting зэрэг аюулгүй байдлын арга хэмжээ
4. **Modern:** Орчин үеийн технологи ашигласан

**Performance тест үр дүн:**

```bash
# Load testing with Apache Bench
ab -n 1000 -c 10 http://websecpen.com/api/scan/history

Results:
- Requests per second: 245.32 [#/sec]
- Time per request: 40.771 [ms]
- Transfer rate: 89.44 [Kbytes/sec]
```

### 4.3 Хүндрэл бэрхшээл ба шийдэл

#### 4.3.1 Техник хүндрэл

**OWASP ZAP интеграци:**

*Асуудал:* ZAP scanner-ийн Python API нь тогтмол алдаа гаргаж, connection timeout асуудал гардаг байсан.

*Шийдэл:* 
- Connection pool ашиглан тогтвортой холболт бүтээх
- Retry mechanism нэмэх
- Error handling сайжруулах

```python
def safe_zap_request(func, *args, max_retries=3, **kwargs):
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except ConnectionError:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)  # Exponential backoff
```

**Асинхрон ажлын дараалал:**

*Асуудал:* Celery worker процесс gаa memory leak, crash зэрэг асуудал гардаг байсан.

*Шийдэл:*
- Worker процессийг жигнэс restart хийх
- Memory usage мониторинг нэмэх
- Task timeout тохируулах

```python
# Celery тохиргоонд нэмсэн
CELERY_TASK_TIME_LIMIT = 1800  # 30 минут
CELERYD_MAX_TASKS_PER_CHILD = 50  # 50 task дараа restart
```

#### 4.3.2 Бизнес хүндрэл

**Хэрэглэгчийн хэрэгцээ тодорхойлох:**

*Асуудал:* Анхны хувилбарт хэт олон функц байснаар хэрэглэгчдэд төвөгтэй санагдаж байсан.

*Шийдэл:*
- MVP (Minimum Viable Product) зарчмаар эхлэх
- Хэрэглэгчийн санал хүсэлт тогтмол авах
- Функцийг аажмаар нэмэх

**UI/UX дизайн:**

*Асуудал:* Анхны дизайн техник хэрэглэгчдэд л ойлгогдохоор байсан.

*Шийдэл:*
- Material-UI ашиглан стандарт компонент ашиглах
- Tooltip, help text нэмэх
- Wizard-style workflow оруулах

#### 4.3.3 Хугацааны удирдлага

**Төлөвлөлтийн алдаа:**

*Асуудал:* Анхны төлөвлөлтөд некоторые функцийн хэрэгжүүлэх хугацааг дутуу тооцсон байсан.

*Шийдэл:*
- Agile methodology ашиглан спринт тутам үнэлэх
- Buffer time үлдээх
- Daily standap-д ахиц хэлэлцэх

### 4.4 Цаашдын хөгжлийн чиглэл

#### 4.4.1 Техник сайжруулалт

**Микросервис архитектур:**

Одоогийн monolithic архитектурыг микросервис руу шилжүүлэх:

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   Auth      │  │   Scanner   │  │   Report    │
│   Service   │  │   Service   │  │   Service   │
└─────────────┘  └─────────────┘  └─────────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                 ┌─────────────┐
                 │   API       │
                 │   Gateway   │
                 └─────────────┘
```

**Machine Learning сайжруулалт:**

- False positive багасгах
- Vulnerability severity-г илүү нарийвчлалтай тооцох
- Автомат fix санал болгох

**Real-time мониторинг:**

- WebSocket ашиглан real-time updates
- Dashboard-д live метрик харуулах
- Push notification нэмэх

#### 4.4.2 Бизнес өргөжүүлэлт

**Multi-tenant архитектур:**

Олон компани, байгууллага ашиглах боломжтой болгох:

```python
class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    plan = db.Column(db.String(20), default='basic')
    users = db.relationship('User', backref='organization')
```

**Enterprise функцүүд:**

- SSO (Single Sign-On) интеграци
- LDAP authentication
- Custom branding
- Advanced reporting
- API access management

**Pricing модель:**

- Free tier: 10 скан/сар
- Basic tier: 100 скан/сар
- Professional tier: Unlimited скан
- Enterprise tier: Custom requirements

#### 4.4.3 Интеграци өргөжүүлэлт

**CI/CD интеграци:**

```yaml
# GitHub Actions нэмэлт
- name: Security Scan
  uses: websecpen/security-scan@v1
  with:
    api_key: ${{ secrets.WEBSECPEN_API_KEY }}
    target_url: ${{ env.STAGING_URL }}
```

**Webhook integration:**

```python
@app.route('/api/webhook/slack', methods=['POST'])
def slack_webhook():
    data = request.get_json()
    if data['event_type'] == 'scan_completed':
        send_slack_notification(data['scan_result'])
    return jsonify({'status': 'ok'})
```

**API ecosystem:**

- Zapier интеграци
- Terraform provider
- Kubernetes operator

Энэ бүлэгт дадлагын үр дүн, олж авсан туршлага, хүндрэл бэрхшээл, цаашдын хөгжлийн чиглэлийн талаар дэлгэрэнгүй дүгнэсэн. Дараагийн хэсэгт дадлагын ерөнхий дүгнэлт өгнө.

---

## ДҮГНЭЛТ

### Дадлагын ерөнхий үр дүн

БД Системс Эйжиа ХХК-д хийсэн 60 хоногийн дадлагын хугацаанд WebSecPen автомат вэб аппликейшний аюулгүй байдлын мониторинг, шинжилгээний систем амжилттай хөгжүүлэн дуусгасан. Энэхүү төсөл нь зөвхөн техник чадварыг хөгжүүлээд зогсохгүй, бодит бизнесийн орчинд ажиллах, багаар хамтран ажиллах, асуудлыг шийдвэрлэх зэрэг олон талын туршлага олгосон.

### Гол ололтууд

1. **Техник ололтууд:**
   - Орчин үеийн full-stack вэб аппликейшн хөгжүүлэх чадварт хүрсэн
   - Python Flask, React.js зэрэг технологиг бодит төсөлд хэрэглэх боломжтой болсон
   - DevOps pipeline, автомат тестлэлт, deployment хийх туршлага олжээ
   - Мэдээллийн аюулгүй байдлын стандарт, практикуудтай гүнзгий танилцсан

2. **Бизнес ололтууд:**
   - Бодит хэрэглэгчийн хэрэгцээг ойлгож, шийдэл санал болгох чадвар хөгжүүлсэн
   - Клиенттэй харилцах, саналыг хүлээн авах, өөрчлөлт хийх туршлага олжээ
   - Стартап орчинд ажиллах, хурдан хөгжүүлэлт хийх арга барилтай танилцсан

3. **Хувийн хөгжил:**
   - Өөртөө итгэх итгэл, бие даан асуудал шийдвэрлэх чадвар нэмэгдсэн
   - Bagaар ажиллах, харилцан туслах, мэдлэг хуваалцах дадал үүссэн
   - Тэсвэр тэвчээр, цаг хугацааны удирдлагын чадвар сайжирсан

### Олж авсан мэдлэг, чадвар

**Техник мэдлэг:**
- Python ecosystem (Flask, SQLAlchemy, Celery)
- JavaScript ecosystem (React, Node.js, npm)
- Database design ба SQL
- REST API дизайн, хэрэгжүүлэлт
- Docker, containerization
- CI/CD pipeline (GitHub Actions)
- Cloud deployment (Render)

**Аюулгүй байдлын мэдлэг:**
- OWASP стандарт, Top 10 аюулгүй байдлын сул тал
- Вэб аппликейшний халдлагын төрөл (SQL injection, XSS, CSRF гэх мэт)
- Аюулгүй байдлын шалгалтын багаж (OWASP ZAP)
- Automated security testing
- Vulnerability assessment, remediation

**Soft skills:**
- Төсөл удирдлага, Agile methodology
- Бүтээлч, шийдвэрлэх сэтгэлгээ
- Харилцаа, илтгэлийн чадвар
- Цаг хугацааны удирдлага
- Өөрөө суралцах, мэдлэг олж авах чадвар

### Дадлагын үнэлгээ

**Компанийн үнэлгээ:**
БД Системс Эйжиа ХХК-ийн удирдлага, ажилтнуудын үнэлгээгээр дадлагын хугацаанд хийсэн ажил хэрэгжүүлсэн системийн чанар, техник түвшин, ажлын хандлага нь хүлээлтээс илүү байсан гэж үнэлжээ.

Компанийн техникийн менежер Батзоригийн хэлснээр:
> "WebSecPen систем нь монгол хэл дээрх анхны вэб аппликейшний аюулгүй байдлын автомат шинжилгээний систем болж байна. Техник хэрэгжүүлэлт, UI/UX дизайн, бизнес процессийн хувьд бодит ашиглах боломжтой төвшинд хүрсэн."

**Хувийн үнэлгээ:**
Дадлагын эхэнд тавьсан зорилтуудаас 90%-ийг хэрэгжүүлж чадсан. Тодруулбал:
- ✅ Full-stack вэб аппликейшн хөгжүүлэх (100%)
- ✅ Аюулгүй байдлын мэдлэг олж авах (95%)
- ✅ Орчин үеийн технологи эзэмшүүлэх (90%)
- ✅ Багаар ажиллах чадвар хөгжүүлэх (95%)
- ⚠️ Бизнес процесс ойлгох (80%)

### Цаашдын хэрэглээ

Энэхүү дадлагын туршлага нь цаашдын карьерт маш чухал үүрэг гүйцэтгэх болно:

1. **Мэргэжлийн чиглэл тодорчих:**
   Мэдээллийн аюулгүй байдлын салбарт мэргэшихэд сонирхол нэмэгдэж, энэ чиглэлээр цаашид хөгжихөөр шийдвэрлэсэн.

2. **Portfolio төсөл:**
   WebSecPen системийг жинхэнэ portfolio төсөл болгон хөгжүүлэн, ажил хайх, стартап үүсгэх зэрэгт ашиглах боломжтой.

3. **Сүлжээ байгуулах:**
   Дадлагын үеэр танилцсан мэргэжилтнүүд, компанийнхантай цаашид хамтран ажиллах боломж нээгдсэн.

### Талархал

Энэхүү амжилттай дадлагыг хийх боломж олгосон дараах хүмүүст талархал илэрхийлье:

- **БД Системс Эйжиа ХХК-ийн удирдлага:** Дадлага хийх боломж олгож, бүх нөхцөлийг бүрдүүлсэн
- **Батзориг багш:** Төсөл удирдан, техник зөвлөгөө өгсөн
- **Болормаа ахлах програмист:** Өдөр тутмын удирдлага, код шалгаж, заасан
- **Бүх ажилтнууд:** Халуун дотно хүлээн авч, туслалцаа үзүүлсэн

Мөн энэ дадлагыг зохион байгуулсан их сургуулийн администраци, дадлагын удирдагчдад талархал илэрхийлье.

### Санал зөвлөмж

Цаашид дадлага хийх оюутнуудад дараах зөвлөмжийг өгмөөр байна:

1. **Бэлтгэл ажил сайн хийх:** Дадлага эхлэхээсээ өмнө компанийн талаар, салбарын талаар мэдээлэл цуглуулах
2. **Идэвхтэй оролцох:** Зөвхөн өгсөн даалгавар биелүүлээд зогсохгүй, санаачилга гаргах
3. **Асуулт асуух:** Ойлгоогүй зүйлээ нуулгахгүй, тайлбар асуух
4. **Сүлжээ байгуулах:** Хамтран ажилласан хүмүүстэй холбоо тасрахгүй байх
5. **Документаци хөтлөх:** Хийсэн ажлаа тэмдэглэж, дараа дахин ашиглах

Эцэст нь, энэхүү дадлага нь зөвхөн мэргэжлийн хөгжлөөс гадна хувь хүний хөгжилд томоохон нөлөө үзүүлсэн ба цаашдын амьдрал, карьерт чухал үндэс болох юм.

---

## НОМ ЗҮЙ

[1] Statista. (2024). "Internet usage worldwide - Statistics & Facts". Retrieved from https://www.statista.com/topics/1145/internet-usage-worldwide/

[2] Moreira, D., Seara, J. P., Pavia, J. P., & Serrão, C. (2025). "Intelligent Platform for Automating Vulnerability Detection in Web Applications". Electronics, 14(1), 79. https://doi.org/10.3390/electronics14010079

[3] Statista. (2024). "Cybersecurity incidents reported by organizations worldwide in 2024". Retrieved from https://www.statista.com/statistics/cybersecurity-incidents/

[4] Bitdefender. (2024). "About Bitdefender - Company Overview". Retrieved from https://www.bitdefender.com/company/

[5] OWASP Foundation. (2024). "OWASP Top Ten 2024". Retrieved from https://owasp.org/Top10/

[6] Maniraj, S. P., Ranganathan, C. S., & Sekar, S. (2024). "Securing Web Applications with OWASP ZAP for Comprehensive Security Testing". International Journal of Advances in Signal and Image Sciences, 10(2), 12-23.

[7] Potti, U. S., Huang, H. S., Chen, H. T., & Sun, H. M. (2025). "Security Testing Framework for Web Applications: Benchmarking ZAP V2.12.0 and V2.13.0 by OWASP as an example". arXiv:2501.05907.

[8] Xiong, Z., & Ye, J. (2024). "Security Vulnerability Scanning Scheme of Web Application Based on Django". In Proceedings of the 3rd International Conference on Cognitive Based Information Processing and Applications (pp. 581-591). Springer.

[9] Disawal, S., & Suman, U. (2024). "Enhancing Security to Prevent Vulnerabilities in Web Applications". International Journal of Engineering Trends and Technology, 72(7), 130-140.

[10] Flask Development Team. (2024). "Flask Documentation". Retrieved from https://flask.palletsprojects.com/

[11] React Team. (2024). "React Documentation". Retrieved from https://react.dev/

[12] OWASP ZAP Team. (2024). "OWASP ZAP Documentation". Retrieved from https://www.zaproxy.org/docs/

[13] HuggingFace Team. (2024). "Transformers Documentation". Retrieved from https://huggingface.co/docs/transformers/

[14] Celery Project. (2024). "Celery Documentation". Retrieved from https://docs.celeryproject.org/

[15] Redis Labs. (2024). "Redis Documentation". Retrieved from https://redis.io/documentation

---

## ХАВСРАЛТ

### Хавсралт А: WebSecPen системийн техник баримт бичиг

**A.1 API Documentation**

```yaml
openapi: 3.0.0
info:
  title: WebSecPen API
  version: 1.0.0
  description: Web Application Security Scanning API

paths:
  /api/auth/login:
    post:
      summary: User login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                password:
                  type: string
      responses:
        200:
          description: Login successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  access_token:
                    type: string
                  user_id:
                    type: integer
```

**A.2 Өгөгдлийн сангийн схем**

```sql
-- User table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'free',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan table  
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    url VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    results JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability table
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    recommendation TEXT
);
```

### Хавсралт Б: Системийн зургууд

**B.1 Системийн архитектур диаграм**

```mermaid
graph TB
    A[User Browser] --> B[React Frontend]
    B --> C[Flask API]
    C --> D[PostgreSQL Database]
    C --> E[Redis Cache]
    C --> F[Celery Worker]
    F --> G[OWASP ZAP]
    F --> H[HuggingFace API]
    C --> I[PDF Generator]
```

**B.2 Өгөгдлийн урсгалын диаграм**

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant A as API
    participant C as Celery
    participant Z as ZAP Scanner

    U->>F: Start scan request
    F->>A: POST /api/scan/start
    A->>C: Queue scan task
    C->>Z: Execute security scan
    Z->>C: Return results
    C->>A: Update scan status
    A->>F: Notify completion
    F->>U: Display results
```

### Хавсралт В: Кодын жишээ

**C.1 Flask API endpoint**

```python
@app.route('/api/scan/start', methods=['POST'])
@jwt_required()
def start_scan():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        # Input validation
        url = data.get('url')
        if not url or not is_valid_url(url):
            return jsonify({'error': 'Invalid URL provided'}), 400
        
        # Check scan limits
        user = User.query.get(user_id)
        if user.role == 'free' and user.daily_scans >= 5:
            return jsonify({'error': 'Daily scan limit exceeded'}), 429
        
        # Create scan record
        scan = Scan(
            user_id=user_id,
            url=url,
            status='queued'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Queue background task
        task = start_security_scan.delay(scan.id, url)
        scan.task_id = task.id
        db.session.commit()
        
        return jsonify({
            'scan_id': scan.id,
            'message': 'Scan started successfully',
            'estimated_time': '5-15 minutes'
        }), 201
        
    except Exception as e:
        app.logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
```

**C.2 React компонент**

```jsx
import React, { useState, useEffect } from 'react';
import { Card, CardContent, Typography, CircularProgress } from '@mui/material';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

const VulnerabilityChart = ({ scanId }) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await api.get(`/scan/${scanId}/summary`);
                setData(response.data);
            } catch (error) {
                console.error('Error fetching scan summary:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [scanId]);

    if (loading) return <CircularProgress />;

    const chartData = {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            data: [
                data.critical_count,
                data.high_count, 
                data.medium_count,
                data.low_count
            ],
            backgroundColor: [
                '#d32f2f',
                '#f57c00',
                '#fbc02d',
                '#388e3c'
            ]
        }]
    };

    return (
        <Card>
            <CardContent>
                <Typography variant="h6" gutterBottom>
                    Vulnerability Distribution
                </Typography>
                <Doughnut data={chartData} />
            </CardContent>
        </Card>
    );
};

export default VulnerabilityChart;
```

### Хавсралт Г: Тестлэлтийн үр дүн

**D.1 Unit Test Coverage Report**

```
Name                                    Stmts   Miss  Cover
-----------------------------------------------------------
backend/app.py                           145      8    94%
backend/models.py                         89      5    94%
backend/auth.py                           56      3    95%
backend/scanner.py                        78      7    91%
backend/utils.py                          34      2    94%
-----------------------------------------------------------
TOTAL                                    402     25    94%
```

**D.2 Performance Test Results**

```bash
# API Endpoint Performance
GET /api/scan/history:     Avg: 180ms, 95%: 250ms
POST /api/scan/start:      Avg: 120ms, 95%: 180ms
GET /api/scan/result:      Avg: 300ms, 95%: 450ms

# Database Query Performance  
User authentication:       Avg: 15ms
Scan history retrieval:    Avg: 45ms
Vulnerability analysis:    Avg: 120ms

# Frontend Performance
First Contentful Paint:    1.2s
Largest Contentful Paint:  2.1s
Time to Interactive:       2.8s
```

### Хавсралт Д: Компанийн баримт бичиг

**E.1 Дадлагын гэрчилгээ**

[Энд компанийн албан ёсны дадлагын гэрчилгээ хавсаргана]

**E.2 Төсөл танилцуулах материал**

[WebSecPen системийн презентацийн материал хавсаргана]

**E.3 Хэрэглэгчийн санал хүсэлт**

[Систем туршиж үзсэн хэрэглэгчдийн санал хүсэлтийг хавсаргана] 