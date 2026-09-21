# Cloud Identity Security Architecture — AWS IAM + Wazuh SIEM Entegrasyonu

Uçtan uca bir cloud identity ve erişim yönetimi mimarisi: least-privilege IAM tasarımı, gerçek testlerle doğrulama, Wazuh SIEM ile gerçek zamanlı tespit ve otomatik müdahale (active response).

## Proje Amacı

Bu proje, küçük ölçekli bir şirket senaryosunda (Developer, Admin, Analyst, Vendor rolleri) AWS üzerinde **kim, neye, nasıl erişebilir** sorusunu tasarlayan, bu tasarımı gerçek testlerle doğrulayan ve tüm identity aktivitesini izleyip şüpheli davranışlara otomatik tepki veren bir güvenlik mimarisini uçtan uca kurmayı hedefler.
<img width="1658" height="384" alt="Screenshot 2026-09-21 180339" src="https://github.com/user-attachments/assets/7bebaf8c-d634-43e4-9807-427d048b0b73" />


## Mimari Genel Bakış

```
Dış Kimlikler (Developer, Admin, Analyst, Vendor)
            │
            ▼
IAM Kullanıcılar + Least-Privilege Policy'ler
            │
            ▼
AWS Kaynakları (S3, EC2, Cross-account erişim)
            │
            ▼
CloudTrail (tüm identity aktivitesini loglar)
            │
            ▼
Wazuh SIEM (tespit + otomatik müdahale)
```

## Katman 1-2: Kimlik ve Yetkilendirme

- Root hesap MFA ile kilitlendi, API access key'i kaldırıldı
- 4 IAM kullanıcı oluşturuldu, her biri kendi least-privilege policy'siyle:

| Rol | Yetkiler | Bilerek Kısıtlanan |
|---|---|---|
| **Developer** | S3 okuma/yazma, var olan EC2 instance'ları başlatma/durdurma | Yeni EC2 instance oluşturma (`ec2:RunInstances`) |
| **Admin** | S3, EC2, IAM üzerinde geniş yetki | Kullanıcı silme (`iam:DeleteUser`) — `Deny` statement ile açıkça engellendi |
| **Analyst** | Sadece okuma (S3, EC2, IAM) | Her türlü yazma/değiştirme işlemi |
| **Vendor** | Sadece tek bir S3 bucket'a okuma erişimi | Hesaptaki her şey — tek kaynağa kilitli |

Örnek policy (Analyst — read-only):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "ec2:Describe*",
        "iam:Get*",
        "iam:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

## Test ve Doğrulama

Her rol, console üzerinden gerçek giriş yapılarak test edildi — "kağıt üzerinde doğru" değil, "gerçekte çalışıyor" kanıtlandı:

- **Analyst** → S3 bucket içeriğini okuyabildi, dosya yükleme denemesi `Access Denied` ile reddedildi
- **Developer** → S3'te dosya yükleyip silebildi, ancak yeni EC2 instance başlatma denemesi `UnauthorizedOperation` ile reddedildi
- **Admin** → yeni IAM kullanıcı oluşturabildi, ancak kullanıcı silme denemesi `Access Denied` ile reddedildi (bilerek konan `Deny` kuralı sayesinde)
- **Vendor** → sadece kendisine ayrılan bucket'ı görebildi, hesaptaki diğer kaynaklara erişemedi

## Katman 3: Kaynaklar

- Test amaçlı S3 bucket'lar oluşturuldu
- Vendor policy'si tek bir bucket ARN'ine kilitlendi (`Resource: "*"` kullanılmadı, bilerek dar tutuldu)

## Katman 4: İzleme ve Tespit

### CloudTrail

Hesaptaki tüm API çağrıları (kim, ne zaman, hangi işlem) CloudTrail ile loglanıp bir S3 bucket'ına yazıldı.

### Wazuh SIEM Entegrasyonu

Wazuh'un `aws-s3` modülü, CloudTrail loglarını düzenli aralıklarla S3'ten okuyacak şekilde yapılandırıldı:

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>10m</interval>
  <run_on_start>yes</run_on_start>
  <skip_on_error>yes</skip_on_error>
  <bucket type="cloudtrail">
    <name>YOUR_CLOUDTRAIL_BUCKET_NAME</name>
  </bucket>
</wodle>
```

> Kimlik doğrulama, sınırlı yetkili (`s3:GetObject`, `s3:ListBucket`) ayrı bir IAM kullanıcısı üzerinden yapıldı — least-privilege prensibi izleme katmanında da uygulandı.

### Custom Detection Rule

Standart CloudTrail kuralları her olayı düşük seviyeli (level 3) bilgi kaydı olarak işaretliyor. `AccessDenied` olaylarını özel olarak yakalayıp yüksek öncelikli alarma çeviren bir kural yazıldı:

```xml
<rule id="100010" level="10">
  <if_sid>80200</if_sid>
  <field name="aws.errorCode">AccessDenied</field>
  <description>AWS CloudTrail: Access Denied - Yetkisiz erişim denemesi tespit edildi ($(aws.userIdentity.arn))</description>
  <group>aws,access_denied,</group>
</rule>
```

**Sonuç:** Analyst kullanıcısının yetkisi dışındaki denemeleri (upload, bucket listeleme vb.) gerçek zamanlı olarak yakalanıp alarm üretti — tek bir test senaryosunda kural 20'den fazla kez tetiklendi.

## Ekstra: Otomatik Müdahale (Active Response)

Projeyi "sadece tespit" seviyesinden "tespit + otomatik tepki" seviyesine taşımak için bir active response mekanizması eklendi.

**Mantık:** `100010` kuralı tetiklendiğinde (bir kullanıcı yetkisiz bir işlem denediğinde), Wazuh otomatik olarak o kullanıcının AWS access key'ini devre dışı bırakan bir script çalıştırır.

### Ayrı, Least-Privilege Bir "Responder" Kullanıcısı

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DisableCompromisedUserKeys",
      "Effect": "Allow",
      "Action": [
        "iam:UpdateAccessKey",
        "iam:ListAccessKeys"
      ],
      "Resource": "arn:aws:iam::YOUR_ACCOUNT_ID:user/*"
    }
  ]
}
```

Bu kullanıcı **sadece** access key'leri listeleyip aktif/pasif yapabiliyor — başka hiçbir yetkisi yok. Otomatik müdahale mekanizması bile least-privilege prensibiyle sınırlandırıldı.

### Active Response Script

```bash
#!/bin/bash

read INPUT_JSON
USERNAME=$(echo "$INPUT_JSON" | grep -oP '"userName":\s*"\K[^"]+')

LOG_FILE="/var/ossec/logs/active-responses.log"

if [ -z "$USERNAME" ]; then
  echo "$(date) - HATA: kullanici adi bulunamadi" >> $LOG_FILE
  exit 1
fi

ACCESS_KEY_ID=$(AWS_PROFILE=wazuh-responder /usr/local/bin/aws iam list-access-keys --user-name "$USERNAME" --query "AccessKeyMetadata[0].AccessKeyId" --output text)

if [ "$ACCESS_KEY_ID" != "None" ] && [ -n "$ACCESS_KEY_ID" ]; then
  AWS_PROFILE=wazuh-responder /usr/local/bin/aws iam update-access-key --user-name "$USERNAME" --access-key-id "$ACCESS_KEY_ID" --status Inactive
  echo "$(date) - BASARILI: $USERNAME - $ACCESS_KEY_ID devre disi birakildi" >> $LOG_FILE
else
  echo "$(date) - UYARI: $USERNAME icin aktif access key bulunamadi" >> $LOG_FILE
fi
```

### Wazuh Konfigürasyonu

```xml
<command>
  <name>disable-aws-user</name>
  <executable>disable-aws-user.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>disable-aws-user</command>
  <location>local</location>
  <rules_id>100010</rules_id>
</active-response>
```

**Kanıtlanan davranış:**
- Programatik erişimi (access key) olan bir kullanıcı yetkisiz bir işlem denediğinde, sistem saniyeler içinde o key'i otomatik olarak devre dışı bırakıyor
- Konsol-only kullanıcılarda (access key'i olmayan) mekanizma çalışıyor ama "devre dışı bırakılacak credential yok" sonucuna varıp güvenli şekilde çıkıyor — hata değil, beklenen davranış

## Threat Model (STRIDE)

| Kategori | Durum | Not |
|---|---|---|
| **Spoofing** | ⚠️ Kısmi | Root'ta MFA var, IAM kullanıcılarında henüz zorunlu değil — bilinen bir iyileştirme alanı |
| **Tampering** | ✅ Kontrollü | S3 versioning ile daha da güçlendirilebilir |
| **Repudiation** | ✅ Güçlü | CloudTrail + Wazuh ile her işlem kullanıcı bazında loglanıyor |
| **Information Disclosure** | ✅ Güçlü | Vendor izolasyonu test edilip kanıtlandı |
| **Denial of Service** | ✅ Kontrollü | `RunInstances` yetkisi bilerek kısıtlandı, kaynak israfı önlendi |
| **Elevation of Privilege** | ✅ Güçlü | Developer'da hiçbir IAM yetkisi yok — en yaygın privilege escalation yolu kapatıldı |

## Kullanılan Teknolojiler

- **AWS IAM** — kimlik ve yetkilendirme
- **AWS CloudTrail** — aktivite loglama
- **AWS S3** — log ve test verisi depolama
- **AWS IAM Access Analyzer** — yetki analizi
- **Wazuh** — SIEM, tespit ve otomatik müdahale
- **AWS CLI** — active response otomasyonu

## Öğrenilen Dersler

- Least-privilege tasarımı, yazıldığında değil **test edildiğinde** anlam kazanıyor
- Detection ve response'u birbirinden ayırmak (ayrı IAM kullanıcıları ile) blast radius'u küçültüyor
- Konsol erişimi ve API erişimi farklı tehdit yüzeyleri — otomatik müdahale tasarlarken ikisi ayrı ele alınmalı
- SIEM entegrasyonlarında path/prefix hataları (örn. `AWSLogs/AWSLogs/`) sessizce veri kaybına yol açabilir, log çıktısı dikkatle izlenmeli

## Sorumluluk Reddi

Bu proje bir lab/öğrenme ortamında kurulmuştur. Gerçek bir üretim ortamına taşınmadan önce: MFA zorunluluğu tüm kullanıcılara genişletilmeli, access key'ler yerine geçici kimlik bilgileri (STS) tercih edilmeli, ve tüm credential'lar bir secrets manager üzerinden yönetilmelidir.
