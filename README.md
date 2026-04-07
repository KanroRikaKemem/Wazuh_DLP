# Wazuh_DLP

>*Một số kiến thức góp nhặt để cày NCKH. Mình sẽ cố gắng viết lại theo ý hiểu của mình.*

## A. Lý thuyết:
### I. Định nghĩa:
- Dữ liệu doanh nghiệp là nguồn tài nguyên chứa đựng nhiều thông tin nhạy cảm (ví dụ như thông tin của khách hàng, nhân viên, sản phẩm hay tài liệu mật về hoạt động kinh doanh), vì thế nên nó sẽ là con mồi béo bở để attacker tấn công vào và trục lợi từ nó.
- Để ngăn chặn sự tấn công, DLP (Data Loss Prevention - Chống thất thoát dữ liệu) là giải pháp giúp ngăn chặn dữ liệu khỏi bị mất, rò rỉ ra ngoài phạm vi công ty hoặc bị truy cập trái phép.
- Công nghệ DLP gồm có hai hướng triển khai chính:

#### Dành cho doanh nghiệp (Enterprise DLP): 
- Độc lập, toàn diện và được triển khai ở cấp độ doanh nghiệp lớn, độ chính xác cao.
- Có một phòng ban chuyên biệt để kiểm soát, phân loại, bảo vệ dữ liệu trên nhiều kênh và tầng khác nhau.
- Có bảng điều khiển trung tâm để quản lý chính sách, sự cố.
- Có thể phân tích nội dung, ngữ cảnh của dữ liệu.
- Các tính năng dành cho máy tính để bàn, server, thiết bị vật lý/ảo để giám sát lưu lượng, thiết bị phần mềm để giám sát dữ liệu.
> Ví dụ: Công ty cài DLP agent lên tất cả máy tính của nhân viên. Khi nhân viên muốn chuyển dữ liệu có chứa từ khoá nào đó sang USB cá nhân, hệ thống sẽ cảnh báo hoặc chặn lại.
- Ưu điểm:
    - Bảo vệ tập trung, toàn diện.
    - Xử lý linh hoạt.
- Nhược điểm:
    - Chi phí cao.
    - Cấu hình phức tạp để vận hành, cần đội ngũ chuyên môn.

#### DLP tích hợp (Integrated DLP): 
- Thường là phần mở rộng trong các sản phẩm hoặc ứng dụng thay vì là hệ thống độc lập.
> Ví dụ: 
> - Microsoft 365 có tích hợp DLP sẵn, cho phép chính sách không cho gửi email ra ngoài chứa số CCCD hoặc số thẻ tín dụng.
> - DLP trong Google Workspace hoạt động bằng cách quét nội dung email, Drive để tìm kiếm các dữ liệu nhạy cảm (thông tin cá nhân, tài chính, dữ liệu sở hữu trí tuệ,...). Khi phát hiện dữ liệu nhạy cảm, nó có thể:
>    - Chặn người dùng gửi hoặc tải dữ liệu.
>    - Mã hoá dữ liệu, chỉ người có quyền mới đọc được.
>    - Gửi cảnh báo cho admin hoặc client.
- Ưu điểm:
    - Dễ triển khai, chi phí thấp.
    - Tích hợp liền mạch với hạ tầng sẵn có.
    - Phù hợp với loại hình doanh nghiệp nhỏ và vừa.
- Nhược điểm:
    - Không thể bảo vệ toàn diện.
    - Thiếu khả năng quản lý tập trung và phân tích nâng cao.
    - Khó mở rộng khi doanh nghiệp muốn phát triển.

### II. Các loại DLP phổ biến:
#### 1. DLP theo thiết bị đầu cuối (Endpoint DLP):
> Sơ lược về thiết bị đầu cuối (Endpoint System):
> ![image](https://hackmd.io/_uploads/S183LUHaxl.png)
>    - Thường gọi là host.
>    - Là nơi:
>        - Khởi phát dữ liệu truyền thông trên mạng.
>        - Đích đến cuối cùng của dữ liệu.

##### a) Khái niệm:
- Endpoint DLP là giải pháp ngăn chặn rò rĩ dữ liệu trên thiết bị của người dùng (laptop, PC, điện thoại di động,...).
- Nó giám sát mọi hoạt động truy cập, sao chép hoặc chỉnh sửa dữ liệu nhạy cảm, trước khi dữ liệu rời khỏi thiết bị.

##### b) Cách hoạt động:
Thường được triển khai dưới dạng agent cài vào máy người dùng. Agent sẽ:
- Theo dõi hành vi của người dùng.
- Phân tích nội dung dữ liệu (nhạy cảm).
- Áp dụng các chính sách bảo vệ do admin định nghĩa:
    - Chặn sao chép.
    - Chặn gửi ra ngoài.
    - Mã hoá file tự động.
    - Cảnh báo nếu phát hiện hành vi đáng ngờ.
    - ...
> Ví dụ: Một nhân viên trong công ty cố gắng gửi file chứa thông tin khách hàng. Endpoint DLP sẽ phát hiện nội dung file chứa thông tin nhạy cảm và ngay lập tức chặn hành động, gửi cảnh báo đến admin và ghi log lại.
- Ưu điểm:
    - Bảo vệ dữ liệu trước khi nó rời khỏi thiết bị.
    - Phát hiện được hành vi cố tình làm rò rỉ nội bộ.
    - Hữu ích khi nhân viên làm việc từ xa hoặc ngoài mạng công ty.
    - Dễ tích hợp vào DLP tổng thể.
- Nhược điểm:
    - Cần cài đặt agent trên từng thiết bị, nếu không tối ưu thì dễ gây quá tải hệ thống.
    - Nếu cấu hình sai thì có thể làm ảnh hưởng đến hiệu năng của máy.
    - Chỉ bảo vệ thiết bị đã cài agent mà không kiểm soát được thiết bị ngoài phạm vi công ty.

##### c) Các thành phần chính:
- Agent trên thiết bị người dùng:
    - Theo dõi file, clipboard, USB, Bluetooth, email, trình duyệt,...
    - Báo cáo về server trung tâm.
- Server quản lý trung tâm (Management Server):
    - Nơi cấu hình chính sách bảo mật.
    - Thu thập log, báo cáo sự cố và quản lý cảnh báo.
- CSDL chính sách và dữ liệu nhạy cảm (Policy Repository): Định nghĩa các loại dữ liệu cần bảo vệ (CCCD, mã nguồn, tài liệu nội bộ,...)

##### d) Một số tính năng tiêu biểu:
- Giám sát tệp tin: Phát hiện việc truy cập, chỉnh sửa, xoá, nén, sao chép, đổi tên file.
- Kiểm soát thiết bị ngoại vi: Cho phép/Chặn USB, ổ cứng ngoài, điện thoại, máy in,...
- Giám sát clipboard và màn hình: Ngăn copy - paste hoặc cap màn hình dữ liệu nhạy cảm.
- Kiểm soát truy cập mạng: Giám sát upload dữ liệu qua web, email, mạng xã hội,...
- Mã hoá dữ liệu cục bộ: Tự động mã hoá file chứa dữ liệu nhạy cảm.
- Báo cáo và cảnh cáo: Gửi thông báo nếu phát hiện hành vi rủi ro hoặc vi phạm chính sách.

##### e) Liên hệ với Enterprise DLP:
- Endpoint DLP là nhánh con của Enterprise DLP - tập trung vào máy người dùng.
- Ngoài ra Enterprise DLP còn có:
    - Network DLP: Giám sát lưu lượng mạng (email, HTTP,...)
    - Storage DLP: Bảo vệ dữ liệu trên server, cloud, database.
- Khi kết hợp ba loại trên, ta sẽ có một hệ thống DLP toàn diện bảo vệ dữ liệu từ thiết bị người dùng $\rightarrow$ Quá trình truyền $\rightarrow$ Đến nơi lưu trữ.

#### 2. DLP theo mạng (Network):
##### a) Khái niệm:
Là công nghệ giám sát và kiểm soát toàn bộ dữ liệu đi qua mạng của doanh nghiệp, nhằm phát hiện và ngăn chặn rò rỉ thông tin nhạy cảm khi dữ liệu rời khỏi phạm vi tổ chức.

##### b) Cách hoạt động:
- Network DLP được triển khai tại điểm giao tiếp mạng (gateway, proxy, span port) nơi toàn bộ lưu lượng Internet hoặc nội bộ đi qua.
- Khi dữ liệu lưu thông, DLP sẽ:
    - Phân tích lưu lượng mạng ở các giao thức như:
        - Email (SMTP, IMAP)
        - Web (HTTP, HTTPS)
        - File Transfer (FTP, SMB)
        - Cloud (Google Drive, OneDrive,...)
    - Nếu cần thì giải mã (kiểm tra nội dung gói HTTPS,...)
    - So khớp dữ liệu với các chính sách hoặc mẫu nhạy cảm:
        - Từ khoá
        - Dữ liệu định dạng (số thẻ tín dụng,...)
        - Fingerprint (mẫu dữ liệu đặc trưng như mã nguồn, tài liệu nội bộ)
    - Thực hiện hành động cho phép/chặn/cảnh báo/mã hoá/gửi báo cáo...
> Ví dụ: Một nhân viên gửi email ra ngoài với file đính kèm chứa dữ liệu cá nhân của khách hàng. Network DLP phát hiện lưu lượng SMTP chứ dữ liệu nhạy cảm sẽ tiến hành tự động chặn email, gửi cảnh báo cho admin và ghi lại log.
- Ưu điểm:
    - Bảo vệ dữ liệu khi đang di chuyển, ngăn việc rò rỉ qua Internet.
    - Được triển khai tập trung nên không cần cài đặt trên từng máy.
    - Có thể phát hiện sớm việc tấn công nội bộ hoặc hành vi bất thường.
    - Dễ tích hợp với hệ thống email, proxy, firewall sẵn có.
- Nhược điểm:
    - Không kiểm soát được dữ liệu offline hoặc nội bộ (copy ra USB).
    - Khó phát hiện dữ liệu được mã hoá hoặc ẩn giấu.
    - Đòi hỏi hạ tầng mạnh và khả năng xử lý cao.
    - Nếu cấu hình sai thì có thể gây trễ mạng.

##### c) Các vị trí triển khai phổ biến:
- Email Gateway DLP: Giám sát và kiểm soát email/nhận (SMTP).
- Web Proxy DLP: Theo dõi file upload hoặc dữ liệu qua web.
- Firewall/IPS tích hợp DLP: Chặn dữ liệu nhạy cảm trong lưu lượng mạng.
- Cloud Access Security Broker (CASB): Giám sát dữ liệu ra/vào cloud.

##### d) Kỹ thuật nhận dạng dữ liệu nhạy cảm:
Network DLP sử dụng nhiều kỹ thuật song song:
- Content Inspection: Đọc và quét nội dung thực tế trong gói tin, email, file,...
- Regular Expresions: Phát hiện mẫu lưu lượng như CCCD, thẻ tín dụng, mã khách hàng,...
- Fingerprint/Exact Data Match: Nhận dạng tài liệu hoặc mẫu dữ liệu cụ thể (hash,...)
- Context Analysis: Xem xét ngữ cảnh (ai gửi, gửi cho ai, qua kênh nào, có mã hoá không,...)

#### 3. DLP theo khám phá (Discovery DLP):
##### a) Định nghĩa:
- Là công nghệ có nhiệm vụ tìm kiếm, phát hiện và phân loại dữ liệu nhạy cảm đã được lưu trữ trong hệ thống của doanh nghiệp:
    - File server
    - Database
    - Ổ đĩa nội bộ
    - Cloud
    - ...
- Mục tiêu là để biết chính xác vị trí của dữ liệu nhạy cảm, ai có quyền truy cập và nó có đang bị lưu trữ sai chỗ hay không.

##### b) Cách hoạt động:
- Thường hoạt động theo ba bước:
    - Scan:
        - DLP tự động quét các vị trí lưu dữ liệu trong mạng nội bộ hoặc cloud.
        - Có thể lên lịch theo định kỳ.
    - Phân tích: Sử dụng các mẫu nhận dạng, các biểu thức chính quy hoặc data fingerprint để xác định dữ liệu nhạy cảm.
    - Hành động: Sau khi phát hiện, hệ thống có thể:
        - Báo cáo cho admin.
        - Mã hoá hoặc di chuyển data đến nơi an toàn.
        - Thay đổi quyền truy cập (nếu cần thiết hoặc khi file đang bị chia sẻ công khai).
        - Xoá hoặc cảnh báo nếu phát hiện dữ liệu vi phạm quy định bảo mật.
- Ưu điểm:
    - Giúp doanh nghiệp biết chính xác vị trí của dữ liệu nhạy cảm.
    - Phát hiện dữ liệu nằm sai vị trí hoặc chia sẻ quá quyền hạn.
    - Hỗ trợ tuân thủ các quy định bảo mật (GDPR, ISO 27001,...).
    - Dễ dàng kết hợp với các loại DLP khác để có chính sách thống nhất (Network, Endpoint,...)
- Nhược điểm:
    - Không ngăn rò rỉ theo thời gian thực vì nó chỉ phát hiện dữ liệu đang nằm im.
    - Cần nhiều tài nguyên và thời gian để quét toàn bộ hệ thống.
    - Cần thêm chính sách phân loại dữ liệu rõ ràng.

##### c) Các vị trí có thể quét:
- File server: Windows file share, NAS, SAN,...
- Database: Oracle, SQL Server, MySQL,...
- Thiết bị đầu cuối: Ổ cứng máy tính,...
- Email: Outlook PST,...
- Cloud: Google Drive, OneDrive,...

##### d) Kỹ thuật phát hiện dữ liệu nhạy cảm:
- Pattern Matching (Regex): Tìm mẫu cụ thể (CCCD, thẻ tín dụng, email,...)
- Dictionary Matching: So sánh với danh sách các từ khoá cấm hoặc nhạy cảm.
- Fingerprint/EDM (Exact Data Match): Nhận dạng dữ liệu bằng hash hoặc mẫu định danh.
- Matching Learning/AI: Phân loại dữ liệu tự động dựa trên nội dung và ngữ cảnh.

##### e) Vai trò trong chiến lượng bảo mật tổng thể:
Sau khi xác định vị trí dữ liệu nhạy cảm, tổ chức mói có thể đặt Endpoint DLP dể bảo vệ khi người dùng truy cập, dùng Network DLP để bảo vệ khi dữ liệu truyền đi và với các loại DLP khác.

#### 4. DLP đám mây (Cloud DLP):
##### a) Định nghĩa:
- Là công nghệ dùng để phát hiện, bảo vệ và kiểm soát dữ liệu nhạy cảm trong các dịch vụ đám mây, hay nói cách khác là phiên bản mở rộng hơn của Enterprise DLP.
- Trong môi trường hiện đại:
    - Nhân viên thường lưu file trên Google Drive hoặc gửi qua email.
    - Dữ liệu công ty di chuyển ra ngoài tường lửa truyền thống khiến cho Network DLP không còn giám sát được.
    - Các ứng dụng SaaS thuộc bên thứ ba nên không thể cài Endpoint DLP vào được
$\rightarrow$ DLP là giải pháp giúp phát hiện dữ liệu nhạy cảm trong cloud, chặn việc chia sẻ trái phép và tự động mã hoá/xoá dữ liệu rủ ro.

##### b) Cách hoạt động:
- Có thể triển khai theo hai mô hình chính:
    - Tích hợp trực tiếp với nền tảng cloud (API - based DLP):
        - Cloud DLP kết nối qua API chính thức của nền tảng (Google Workspace, Microsoft 365,...)
        - DLP có thể quét nội dung file, email, tài liệu, tin nhắn được lưu trữ trong cloud.
        - Không cần cài agent nên triển khai rất nhanh.
        - Hoạt động với cả dữ liệu đang nằm yên hoặc đang được chia sẻ trong môi trường cloud.
    > Ví dụ: Cloud DLP phát hiện file trên Google Drive chứa số thẻ tín dụng và được chia sẻ công khai, hệ thống sẽ tự động thu hồi quyền chia sẻ, cảnh báo cho chủ sở hữu và báo cáo cho admin.
    - Thông qua CASB (Cloud Access Security Broker):
        - CASB là lớp trung gian giữa người dùng và cloud, giám sát mọi lưu lượng truy cập cloud.
        - Khi kết hợp với DLP, CASB có thể: 
            - Phân tích dữ liệu real - time khi người dùng upload/download file.
            - Chặn hoặc mã hoá dữ liệu nhạy cảm trước khi rời khỏi phạm vi tổ chức.
            - Phát hiện và ngăn chặn việc chia sẻ hai quyền trên cloud.
    > Ví dụ: Khi nhân viên upload tài liệu `Báo cáo khách hàng.pdf` lên OneDrive, CASB + DLP phát hiện dữ liệu nhạy cảm và chặn hành động upload hoặc tự động mã hoá file.
- Ưu điểm:
    - Bảo vệ dữ liệu ở mọi nơi trên cloud, kể cả ngoài hệ thống nội bộ.
    - Không cần cài agent trên thiết bị người dùng.
    - Hỗ trợ mỗi trường làm việc hybrid/remote.
    - Dễ tích hợp với các DLP doanh nghiệp hiện có.
    - Phát hiện và sửa lỗi cấu hình chia sẻ sai.
- Nhược điểm:
    - Phụ thuộc vào API của nhà cung cấp cloud, đôi khi bị giới hạn tính năng.
    - Khó kiểm soát dữ liệu trên ứng dụng không chính thức.
    - Cần cấu hình chính sách tinh vi để tránh false positive.
    - Một số nền tảng yêu cầu bản quyền DLP riêng biệt.

##### c) Kỹ thuật nhận diện dữ liệu nhạy cảm:
- Content Inspection: Đọc và phân tích nội dung trong file, email, tin nhắn,...
- Regex/Pattern Matching: Nhận dạng dữ liệu (CCCD,...)
- Matching Learning/AI: Xác định dữ liệu dựa trên ngữ cảnh.
- OCR (Optical Character Recognition): Quét hình ảnh hoặc PDF để phát hiện văn bản nhạy cảm.

##### d) Tính năng chính:
- Phát hiện dữ liệu nhạy cảm: Quét và xác định
- Kiểm soát chia sẻ: Ngăn người dùng chia sẻ tài liệu công khai hoặc ra ngoài domain.
- Mã hoá/Xoá tự động: Thực thi hành động bảo vệ khi phát hiện vi phạm.
- Báo cáo và cảnh báo: Gửi thông báo real - time khi có rủi ro.
- Tích hợp chính sách DLP tổng thể: Đồng bộ chính sách với các loại DLP khác để thống nhất kiểm soát.

##### e) Các giải pháp Cloud DLP phổ biến:
- Google Cloud DLP API
- Microsoft Purview DLP (M365, OneDrive, Teams)
- ...

#### 5. DLP dựa trên nội dung (Content - aware DLP):
##### a) Định nghĩa:
- Là công nghệ phân tích trực tiếp nội dung dữ liệu để nhận diện, giám sát và bảo vệ thông tin nhạy cảm khỏi bị rò rỉ dù dữ liệu đó đang được lưu trữ, sử dụng hoặc truyền ra ngoài tổ chức.
- Khác với những hệ thống chỉ dựa vào vị trí hoặc loại file, DLP dạng này đọc hiểu bên trong tài liệu, email hoặc dữ liệu được truyền đi để xác minh chính xác bản chất của thông tin.
- Mục tiêu là bảo vệ dữ liệu thật sự quan trọng.

##### b) Cách hoạt động:
- Thường trải qua ba giai đoạn chính:
    - Phân tích và trích xuất nội dung:
        - Hệ thống DLP mở các file như Word, PDF, Excel, email, log,...
        - Trích xuất văn bản (kể cả trong file nén, file hình ảnh hoặc file mã hoá nếu có quyền truy cập giải mã).
    - Nhận diện thông tin nhạy cảm: DLP sử dụng các kỹ thuật như:
        - Regular Expressions (Regex): Phát hiện các chuỗi mẫu (CCCD, email,...)
        - Fingerprinting: So sánh nội dung với một cơ sở dữ liệu gốc đã được đánh dấu là nhạy cảm.
        - Machine Learning/AI: Phân loại tự động theo ngữ cảnh.
    - Thực thi chính sách bảo vệ: Sau khi xác định được dữ liệu nhạy cảm, DLP sẽ:
        - Cảnh báo người dùng nếu họ cố gửi dữ liệu ra ngoài.
        - Chặn hành động: Không cho gửi email, tải file lên cloud hoặc sao chép ra USB,...
        - Mã hoá dữ liệu: Tự động mã hoá trước khi truyền hoặc lưu trữ.
        - Ghi log và báo cáo: Để phục vụ việc giám sát và kiểm toán bảo mật.
- Ưu điểm:
    - Phát hiện chính xác nhờ việc hiểu nội dung thực tế mà không dựa vào mỗi loại file.
    - Bảo vệ toàn diện (áp dụng được trên file, email, mạng, cloud,...)
    - Giảm thiểu rủi ro con người: Dù cho cố ý hay vô tình, dữ liệu vẫn được kiểm soát.
    - Hỗ trợ tuân thủ pháp lý: Tự động xác định và bảo vệ thông tin nhạy cảm.
- Hạn chế:
    - Tốn tài nguyên xử lý do cần quét và phân tích từng byte nội dung.
    - Độ trễ trong giao tiếp nếu gặp file có dung lượng lớn.
    - Cần cập nhật liên tục mẫu vì định dạng thông tin có thể thay đổi.
    - Có nguy cơ cảnh báo sai nếu quy tắc nhận dạng chưa được tinh chỉnh tốt.

##### c) Một số nhà cung cấp tiêu biểu:
Các nền tảng có khả năng phân tích ngữ nghĩa, mẫu dữ liệu và hành vi người dùng để phát hiện nguy cơ rò rỉ thông tin:
- Synmatec Content-aware DLP
- Forcepoint DLP
- McAfee Total Protection DLP
- Microsoft Purview DLP (Trước đây là Microsoft 365 DLP)
- ...

#### 6. DLP dựa trên ngữ cảnh (Context - based DLP):
##### a) Định nghĩa:
- Là công nghệ phân tích các yếu tố xung quanh dữ liệu chứ không đi sâu vào nội dung bên trong.
- Thay vì đọc toàn bộ tệp hoặc văn bản, nó xem xét bối cảnh sử dụng dữ liệu (ai đang gửi, gửi đi đâu, gửi bằng phương tiện gì, loại tệp gì, hành vi như thế nào,...) để phát hiện nguy cơ rò rỉ thông tin.

##### b) Cơ chế hoạt động:
- DLP dựa trên ngữ cảnh phân tích siêu dữ liệu (metadata) và luồng hoạt động liên quan đến dữ liệu.
- Các yếu tố thường được xét đến gồm:
    - Danh tính người dùng:
        - Ai là người thực hiện hành động (nhân viên, admin, người ngoài,...)
        - Có quyền hợp lệ với dữ liệu không?
        - Tài khoản có hành vi bất thường không (tải lượng lớn, truy cập ngoài giờ)?
    > Ví dụ: Một nhân viên thường chỉ tải vài file mỗi ngày nhưng đột ngột tải hàng trăm file trong đêm $\rightarrow$ Có sự bất thường.
    - Nguồn và đích đến của dữ liệu:
        - Dữ liệu đang đi từ đâu đến đâu (nội bộ, Internet, USB, email ngoài, cloud)?
        - Đích đến có nằm trong danh sách tin cậy không?
        - Dữ liệu có được chuyển ra ngoài phạm vi được phép không?
    - Loại tệp và phương thức truyền:
        - Hệ thống chỉ cho phép gửi một số định dạng nhất định (`PDF`, `DOCS`,...).
        - Nếu phát hiện tệp nén (`.zip`, `.rar`) hoặc mã hoá, nó có thể tạm dừng gửi để kiểm tra thủ công.
        - Giám sát các kênh như email, cloud hoặc ứng dụng như Teams,...
    - Hành vi sử dụng dữ liệu: Những dấu hiệu tiềm ẩn việc rò rỉ dữ liệu, dù nội dung không bị đọc trực tiếp:
        - Sao chép hàng loạt ra ổ đĩa ngoài.
        - Chụp mà hình tài liệu mật.
        - Gửi cùng một file tới nhiều người khác nhau trong thời gian ngắn.
        - ...
- Ưu điểm:
    - Nhẹ hơn Content-aware DLP: Không cần quét toàn bộ nội dung, tiết kiệm tài nguyên.
    - Phát hiện sớm hành vi đáng ngờ, kể cả khi dữ liệu đã được mã hoá (vì không đọc nội dung).
    - Phù hợp cho giám sát hành vi người dùng (UBA/UEBA).
    - Dễ triển khai, có thể hoạt động cấp mạng hoặc hệ điều hành.
- Hạn chế:
    - Không phát hiện được chính xác dữ liệu nhạy cảm.
    - Dễ xảy ra false negative (ví dụ một file có chứa thông tin mật nhưng không bị dán nhắc đặc biệt nên có thể lọt qua).
    - Phụ thuộc vào nhiều chính sách quy định ngữ cảnh (ai, ở đâu, khi nào, phương thức,...).
    - Cần tinh chỉnh chính xác để không làm phiền người dùng với cảnh báo giả.

##### c) Một số nhà cung cấp tiêu biểu:
Các nền tảng sau thường kết hợp với Content-aware trong cùng một bộ chính sách để vừa hiểu hành vi vừa hiểu nội dung:
- Forcepoint DLP Contextual Analysis
- Symantec DLP Contextual Policies
- Microsoft Defender for Endpoint (contextual data monitoring)
- Digital Guardian DLP
- ...

### III. Cơ chế hoạt động chung:
- Phân loại dữ liệu: Để xác định đâu là thông tin nhạy cảm cần được bảo vệ đặc biệt cần sử dụng nhiều kỹ thuật tinh vi để nhận diện các loại dữ liệu khác nhau:
    - Thông tin cá nhân (PII): Tên, địa chỉ, SĐT, email,...
    - Thông tin tài chính (PII): Số thẻ tín dụng, STK,...
    - Dữ liệu sở hữu trí tuệ (IP): Bí mật kinh doanh, bản quyền, sáng chế,...
    - Dữ liệu được quy định: Dữ liệu y tế, dữ liệu giáo dục, dữ liệu chính phủ,...
- Quét dữ liệu: Sử dụng nhiều phương pháp quét tiên tiến để tìm kiếm bất kỳ dấu hiệu nào của dữ liệu nhạy cảm.
- Phát hiện và ngăn chặn: Khi phát hiện dữ liệu nhạy cảm, DLP sẽ ngay lập tức hành động để ngăn chặn mọi truy cập trái phép:
    - Chặn người dùng gửi hoặc tải xuống dữ liệu.
    - Mã hoá dữ liệu để chỉ những người được uỷ quyền mới có thể đọc được.
    - Gửi cảnh báo cho admin hoặc người dùng về vi phạm tiềm ẩn.
- Giám sát và báo cáo: DLP luôn giám sát hệ thống 24/7 để đảm bảo dữ liệu được bảo vệ mọi lúc, ghi lại tất cả hoạt động liên quan đến dữ liệu nhạy cảm và cung cấp báo cáo chi tiết để có thể nắm bắt mọi tình hình.

### IV. Sự quan trọng với doanh nghiệp:
- Việc mất dữ liệu có thể dẫn đến những tổn thất không đáng có, thậm chí là dính án hình sự. Nó cũng có thể tác động bất lợi đến hoạt động của công ty.
> Một trường hợp cho hậu quả của việc làm mất dữ liệu đó chính là các giám đốc điều hành dữ liệu của công ty có thể bị mất việc. Sau những vụ vi phạm dữ liệu nghiêm trọng gây tổn hại cho công ty họ và khiến họ bị phạt hàng triệu USD, các giám đốc điều hành hàng đầu tại Target và Equifax.
- Nếu các hình phạt không hạ bệ được công ty thì chắc chắn xảy ra sự đánh mất lòng tin của khác hàng và công chúng.
> Dựa trên nghiên cứu của Zogby Analytics trên 1006 doanh nghiệp có tối đa 500 nhân viên, một nghiên cứu năm 2019 của National Cyber Security Alliance đã tiết lộ rằng 10% tổ chức đã phá sản, 25% nộp đơn xin phá sản và 37% bị tổn thất tài chính sau một cuộc tấn công vi phạm dữ liệu.

### V. Lợi ích:
- Bảo vệ dữ liệu nhạy cảm: DLP tạo bức tường lửa bảo vệ dữ liệu quan trọng nhằm ngăn chặn các hành vi truy cập trái phép, sử dụng sai mục đích hay rò rỉ thông tin.
- Tuân thủ quy định pháp lý: Giúp doanh nghiệm tuân thủ các quy định pháp lý về bảo mật dữ liệu, tránhc các vi phạm và hình phạt nặng nề.
- Tăng cường uy tín thương hiệu: Việc bảo vệ dữ liệu khách hàng một cách hiệu quả thể hiện sự chuyên nghiệp và uy tín của doanh nghiệp, giúp nâng cao niềm tin và thu hút khách hàng tiềm năng.
- Nâng cao hiệu quả hoạt động: Giúp tối ưu hoá quy trình quản lý dữ liệu, giảm thiểu thời gian và chi phí xử lý các vấn đề liên quan đến rò rỉ dữ liệu.
- Giảm thiểu rủi ro tài chính: Giúp ngăn chặn các hành vi gian lận, trộm cắp thông tin tài chính, bảo vệ tài sản doanh nghiệp và giảm thiểu rủi ro tổn thất về mặt tài chính.

### VI. Ứng dụng trong bảo vệ dữ liệu doanh nghiệp:
- Bảo vệ/Tuân thủ thông tin cá nhân: DLP là giải pháp an ninh mạng tiên tiến giúp doanh nghiệp bảo vệ thông tin cá nhân một cách hiệu quả và tuân thủ các quy định về bảo mật dữ liệu:
    - Xác định và phân loại dữ liệu cá nhân: Nó có thể quét và phân loại dữ liệu trong hệ thống, xác định các thông tin cá nhân nhạy cảm như tên, địa chỉ, SĐT, email,...
    - Kiểm soát truy cập và sử dụng: Giới hạn quyền truy cập vào dữ liệu cá nhân, chỉ cho phép những người có thẩm quyền sử dụng thông tin cho mục đích hợp pháp.
    - Ngăn chặn rò rỉ dữ liệu: Giúp giám sát và ngăn chặn việc sao chép, truyền tải, chia sẻ trái phép dữ liệu cá nhân, giảm thiểu nguy cơ rò rỉ thông tin.
    - Mã hoá dữ liệu: DLP mã hoá dữ liẹu cá nhân khi lưu trữ và truyền tải, đảm bảo an toàn thông tin ngay cả khi bị tấn công mạng.
    - Đáp ứng các yêu cầu pháp lý: Giúp hỗ trợ doanh nghiệp tuân thủ các quy định về bảo mật dữ liệu cá nhân như GDPR, CCPA, Luật An ninh mạng Việt Nam,...
    - Giảm thiểu rủi ro pháp lý: Việc tuân thủ các quy định giúp doanh nghiệp tránh các khoản phạt tiền và hình phạt do vi phạm luật bảo mật dữ liệu.
- Bảo vệ quyền sở hữu trí tuệ:
    - Quyền sở hữu đóng vai trò quan trọng trong việc thúc đẩy sáng tạo và phát triển kinh tế. Tuy nhiên việc bảo vệ Sở hữu trí tuệ đang gặp nhiều thách thức trong thời đại công nghệ số, đặc biệt là nguy cơ lãng phí tài sản trí tuệ do rò rỉ dữ liệu.
    - DLP là công cụ đắc lực giúp doanh nghiệp bảo vệ Sở hữu trí tuệ hiệu quả:
        - Giám sát và kiểm soát truy cập: Giúp giám sát mọi hoạt động truy cập, sử dụng, sao chép, truyền tải dữ liệu Sở hữu trí tuệ, ngăn chặn hành vi truy cập trái phép và rò rỉ thông tin.
        - Phát hiện và ngăn chặn các mối đe doạ: Sử dụng các thuật toán tiên tiến để phát hiện các hành vi nghi ngờ, cảnh báo và ngăn chặn các cuộc tấn công mạng nhắm vào dữ liệu Sở hữu trí tuệ.
        - Quản lý bản quyền và thương hiệu: Giúp quản lý hiệu quả sử dụng việc sử dụng bản quyền và thương hiệu, đảm bảo tuân thủ các quy định về Sở hữu trí tuệ.
        - Giám sát hoạt động vi phạm Sở hữu trí tuệ: Có thể phát hiện các hành vi vi phạm Sở hữu trí tuệ như sao chép trái phép, giả mạo thương hiệu,... giúp doanh nghiệp có biện pháp xử lý kịp thời.
        - Cung cấp bằng chứng trong các vụ kiện tụng: Giúp lưu trữ nhật ký chi tiết về mọi hoạt động liên quan đễn dữ liệu Sở hữu trí tuệ, cung cấp bằng chứng quan trọng trong các vụ kiện tụng.
- Khả năng hiển thị dữ liệu: Đóng vai trò quan trọng trong việc bảo mật dữ liệu doanh nghiệp, cho phép doanh nghiệp xác định vị trí, phân loại và quản lý dữ liệu nhạy cảm một cách hiệu quả:
    - Xác định các loại dữ liệu nhạy cảm: DLP sử dụng các kỹ thuật tiên tiến như quét nội dung, phân tích ngữ cảnh và học máy để xác định các loại dữ liệu nhạy cảm trong hệ thống của doanh nghiệp.
    - Quản lý bảo mật: Dữ liệu được phân loại theo mức độ bảo mật, ví dụ như thông tin bí mật, thông tin nội bộ, thông tin cá nhân,... giúp doanh nghiệp dễ dàng quản lý và áp dụng các biện pháp bảo mật phù hợp.
    - Cung cấp các báo cáo chi tiết về tình trạng bảo mật dữ liệu: Giúp doanh nghiệp đánh giá hiệu quả của các biện pháp bảo mật và đưa ra các quyết định phù hợp. Doanh nghiệp có thể phân tích dữ liệu để hiểu rõ hơn về các rủi ro bảo mật và xu hướng truy cập dữ liệu, từ đó điều chỉnh chính sách bảo mật cho phù hợp.

### VII. Lưu ý khi triển khai:
Để triển khai DLP hiệu quả, người dùng cần lưu ý một số điểm:
- Xác định dữ liệu cần bảo vệ: Trọng tâm dữ liệu cần bảo vệ là gì? Dữ liệu nào được xem là nhạy cảm? PII, thông tin tài chính hay bí mật kinh doanh?...
- Lựa chọn mức độ bảo mật phù hợp: DLP cung cấp nhiều cấp độ bảo mật khác nhau, việc lựa chọn mức độ phù hợp là vô cùng quan trọng.
- Vạch ra quy tắc rõ ràng: Quy tắc DLP là kim chỉ nam cho hệ thống hoạt động nên phải đảm bảo quy tắc được xây dựng rõ ràng, dễ hiều và phù hợp với văn hoá doanh nghiệp. Việc này giúp người dùng tuân thủ quy tắc dễ dàng hơn, đồng thời giảm thiểu nguy cơ truy cập trái phép.
- Lắng nghe phản hồi từ người dùng: Việc thu thập ý kiến từ người dùng giúp đánh giá hiệu quả hệ thống, đồng thời điều chỉnh quy tắc phù hợp hơn với nhu cầu thực tế.
- Thường xuyên cập nhật hệ thống: DLP là một quá trình liên tục nên phải kiên trì nâng cao hệ thống theo thời gian. Việc cập nhật quy tắc, bổ sung dữ liệu nhạy cảm và theo dõi hiệu quả hoạt động giúp DLP luôn bền bỉ bảo vệ dữ liệu.
- Những lưu ý khác:
    - Lựa chọn giải pháp DLP phù hợp với nhu cầu, ngân sách,...
    - Đào tạo người dùng về DLP là vô cùng quan trọng để đảm bảo hệ thống hoạt động hiệu quả.
    - Theo dõi và giám sát thường xuyên hoạt động của hệ thống DLP để đảm bảo dữ liệu được bảo vệ an toàn.

## B. OPEN DLP:
### I. Tổng quan và định nghĩa:
- OpenDLP là một chương trình ngăn chặn mất mát dữ liệu dạng mã nguồn mở và miễn phí theo giấy phép GPL (General Public License).
- Mục đích chính: 
    - Giúp các tổ chức xác định dữ liệu nhạy cảm đang nằm yên (data at rest) trên các hệ thống nội bộ của họ.
    - Thông tin được tạo ra từ OpenDLP có thể được sử dụng để giảm thiểu rủi ro liên quan đến việc rò rỉ dữ liệu.
- Đối tượng mục tiêu: Công cụ này được coi là phù hợp với các chuyên gia tư vấn kiểm tra thâm nhập, admin hệ thống, mạng hoặc bảo mật và các chuyên gia tư vấn tuân thủ.
- Bối cảnh sử dụng: Là lựa chọn tốt cho các startup hoặc doanh nghiệp vừa và nhỏ (SME) có ngân sách eo hẹp và coi trọng tính linh hoạt, khả năng tuỳ chỉnh.

### II. Kiến trúc và hoạt động kỹ thuật:
OpenDLP được quản lý tập trung và có thể phân phối rộng rãi, hoạt động dựa trên cả cơ chế agent (có cài đặt phần mềm trên máy trạm) và agentless (không cần cài đặt).

#### 1. Các thành phần chính:
Hoạt động theo mô hình server - agent model. Gồm hai thành phần chính:
- OpenDLP Server: 
    - Máy chủ trung tâm: Giao diện quản lý chạy trên web Apache (PHP + MySQL).
    - Ngôn ngữ lập trình: Mã nguồn được viết bằng Perl.
    - Database được lưu trong MySQL.
    - Sử dụng `libcurl` để giao tiếp với máy chủ và giao tiếp này sử dụng SSL (Security Socket Layer).
    - OpenDLP yêu cầu NetBIOS, một số môi trường có thể cấm nó.
    - Dùng để cấu hình, khởi động và giám sát quá trình quét dữ liệu.
    - Cho phép tạo nhiều chiến dịch quét, xem và báo cáo kết quả, xuất dữ liệu phát hiện được.
- OpenDLP Agent:
    - Chương trình nhỏ cài trên máy khách (endpoint), thường là Windows.
    - Agent quét ổ đĩa, thư mục hoặc hệ thống file để tìm kiếm dữ liệu khớp với các mẫu nhạy cảm.
    - Sau khi quét xong, agent gửi kết quả về máy chủ OpenDLP qua kết nối mã hoá.
- Đặc điểm:
    - Tiết kiệm chi phí.
    - Đòi hỏi chuyên môn IT để tuỳ chỉnh và bảo trì, có thể làm tăng chi phí dài hạn.

#### 2. Đặc điểm kỹ thuật của Windows Agent:
- Hệ điều hành: Chạy trên Windows 2000 trở lên.
- Ngôn ngữ lập trình: Được viết bằng C, không yêu cầu .NET Framework.
- Hoạt động: Agent được triển khai tới các máy chủ Windows cùng với một cấu hình và với độ ưu tiên thấp, do đó người dùng không nhận biết được sự hiện diện của nó. 
- Việc triển khai được thực hiện bằng cách sử dụng Samba và thông tin xác thực Windows.
- Phục hồi tự động: Agent được cài đặt dưới dạng một dịch vụ, việc này giúp nó tự động tiếp tục hoạt động sau khi hệ thống khởi động lại mà không cần người dùng can thiệp.
- Truyền kết quả: Agent gửi kết quả một cách an toàn đến máy chủ trung tâm theo khoảng thời gian do người dùng định nghĩa thông qua kết nối SSL đáng tin cậy hai chiều. Sau khi hoàn thành, agent sẽ bị gỡ bỏ.
- Toàn bộ quá trình trên là hoàn toàn minh bạch đối với người dùng Windows và không xâm phạm.
- Quản lý Agent: Sau khi cài đặt, có một hệ thống giao tiếp đơn giản giữa máy chủ trung tâm và các agent. Ứng dụng web có thể tự động triển khai và khởi động agent, cũng như tự động dừng, gỡ cài đặt và xoá agent qua Netbios/SMB khi hoàn thành. Nó cũng cho phép tạm dừng, tiếp tục và xoá bỏ agent một cách cưỡng bức khỏi các hệ thống hoặc các đợt quét cụ thể.

#### 3. Các loại quét và cách phát hiện dữ liệu nhạy cảm:
OpenDLP có khả năng đồng thời xác định dữ liệu nhạy cảm trên hàng trăm hoặc nghìn máy tính Microsoft Windows, hệ thống UNIX, database mySQL hoặc MSSQL từ một ứng dụng web tập trung, với điều kiện nó có thông tin đăng nhập phù hợp.

##### a) Các loại quét có sẵn (Phiên bản OpenDP 0.4):
- Quét hệ thống tệp Windows không agent (qua SMB).
- Quét chia sẻ mạng Windows không agent.
- Quét hệ thống tệp UNIX không agent (qua SSH sử dụng sshfs).
- Quét database Microsoft SQL Server (không agent).
- Quét database MySQL (không agent).

##### b) Phạm vi quét:
- Đĩa mềm (floppy).
- Ổ đĩa USB (thumb drive).
- Đầu đọc thẻ flash (flash card reader).
- Ổ cứng HDD.
- Ổ flash (flash driver).
- CD-ROM.
- Đĩa RAM.

##### c) Các bộ lọc:
- Nó có sẵn white/blacklists để ngăn chặn việc quét một số tệp nhất định.
- Có hỗ trợ bộ lọc dựa trên phần mở rộng tệp.

##### d) Cơ chế phát hiện:
- Tìm kiếm theo mẫu: OpenDLP sử dựng PCREs (Perl Compatible Regular Expressions) để xác định dữ liệu nhạy cảm bên trong các tệp.
    - RegEx tích hợp sẵn: OpenDLP chứa các biểu thức RegEx tích hợp sẵn cho tất cả các loại thẻ tín dụng lớn, số an sinh xã hội,...
    - Giảm thiểu lỗi dương tính giả (False Positives): Thực hiện các kiểm tra bổ sung đối với các số thẻ tín dụng tiềm năng để giảm thiểu lỗi trên.
- Tuỳ chỉnh quy tắc quét: Admin có thể thêm mẫu dữ liệu riêng tuỳ theo nhu cầu nội bộ.
- Quét theo danh sách máy tính: Có thể quét nhiều endpoint trong mạng LAN cùng lúc.

##### e) Các tính năng chính:
- Phát hiện dữ liệu nhạy cảm: Quét theo mẫu regex, kiểm tra file hệ thống, registry, database.
- Quản lý tập trung: Giao diện web quản lý tất cả các chiến dịch quét, xem tiến trình và kết quả.
- Tuỳ chỉnh linh hoạt: Tạo, chỉnh sửa mẫu regex, giới hạn thư mục hoặc định dang file.
- Báo cáo kết quả: Xuất file CSV, HTML hoặc hiển thị trực tiếp trên dashboard.
- Tích hợp nhẹ: Cài đặt đơn giản, không yêu cầu license.

### III. Quản lý và kết quả:
#### 1. Quy trình quét:
- Tạo một hồ sơ quét bao gồm thông tin tài khoản Windows (admin cục bộ hoặc tên miền) và các biểu thức chính quy cần tìm kiếm.
- Đối với quét SMB không agent, cần có tài khoản admin và quyền truy cập vào các chia sẻ quản trị mặc định (C\$, D\$,...) trên các hệ thống mục tiêu.
- Nên thực hiện quét trong giờ không sản xuất và quét một số lượng máy nhỏ cùng một lúc.

#### 2. Kết quả:
- Khi quá trình quét hoàn tất, người dùng có thể xem kết quả thông qua giao diện WebGUI và phát hiện lỗi False Positive.
- Có thể xuất kết quả sang XML để xử lý thêm.
- Sau khi xác minh các tệp được xác định là chứa thông tin nhạy cảm, nên thực hiện các bước chuyên sâu hơn như xác định ai có quyền truy cập và thay đổi Danh sách Kiểm soát truy cập (ACLs) nếu cần.

### IV. Hạn chế:
- Phạm vi dữ liệu hạn chế: OpenDLP chỉ tập trung vào dữ liệu đang nằm yên (data at rest) được lưu trữ trên các thiết bị đầu cuối (endpoints). Nó không giải quyết dữ liệu đang chuyển động (in motion) hoặc đang được sử dụng (in use) (như cloud, SaaS,...).
- Hiệu suất máy chủ: Chưa được chứng minh trên máy chủ Windows hoặc các clusters nên cần phải kiểm tra cẩn thận.
- Bị đánh bại bởi mã hoá: Vì OpenDLP chỉ tìm kiếm các biểu thức chính quy trong cleartext nên mã hoá sẽ vô hiệu hoá công cụ này.
- Độ phức tạp và hỗ trợ:
    - Độ phức tạp ở mức vừa phải.
    - Các tính năng chỉ ở mức nền tảng và cần tuỳ chỉnh để mở rộng.
    - Không có hỗ trợ chuyên nghiệp mà chỉ dựa vào cộng đồng mã nguồn mở.
    - Chỉ sử dụng biểu thức chính quy (regex only) để phân tích nội dung, điều này hạn chế nội dung có thể quét được và không có khả năng phân tích nội dung nâng cao.
    - Hạn chế định dạng, không thể quét các định dạng tệp không phải văn bản thuần tuý hoặc một số định dạng tệp nén hoặc database.
- Bảo mật mã nguồn đang hơi lộn xộn, có thể là mối lo ngại về bảo mật.
- Thiếu tính năng ghi log.
- Đòi hỏi kiến thức IT chuyên sâu để cá nhân hoá và duy trì, điều này có thể làm tăng tổng chi phí sở hữu khi tính đến việc giám sát và update liên tục.
- Giao diện đơn giản, thiếu tính năng quản lý người dùng nâng cao.

### V. Các giải pháp phổ biến (Updated on Oct 9 2025):
#### 1. MyDLP Community Edition:
- Là một trong những giải pháp phổ biến nhất trên thị trường.
- Được xây dựng để giám sát và ngăn chặn rò rỉ dữ liệu nhạy cảm.
- Nổi bật với nhiều tính năng kiểm tra dữ liệu qua nhiều kênh khác nhau:
    - Kiểm tra dữ liệu: Hỗ trợ IM (tin nhắn tức thời), FT (Truyền tệp), web, email, máy in và các thiết bị lưu trữ di động.
    - Quản lý chính sách: Quản trị và thực thi các chính sách DLP.
    - Ghi log: Thu thập và hiển thị tất cả các event logs trên một dashboard duy nhất.
    - Quản lý vai trò: Tạo, chỉnh sửa và quản lý các vai trò khác nhau.
    - Tích hợp với Microsoft Exchange.
    - Ngăn chặn email: Lọc blacklist các email chứa địa chỉ BBC nằm ngoài công ty.
    - Triển khai chính sách: Triển khai hoặc cập nhật các chinh sách mới qua Microsoft AD hoặc SCCM.
    - Lọc dữ liệu: Lọc và chặn luồng dữ liệu mang thông tin nhạy cảm.
    - Tuân thủ quy định: Quét dữ liệu nhạy cảm để đảm bảo tuân thủ các quy định bảo mật dữ liệu.
- Ưu điểm:
    - Vì là mã nguồn mở nên mang lại lợi thế chi phí và tính linh hoạt cho việc tuỳ chỉnh.
    - Cung cấp bảng điều khiển hợp nhất để quản lý các chính sách bảo vệ dữ liệu trên toàn tổ chức.
- Nhược điểm:
    - Thiếu sự hỗ trợ khách hàng chuyên biệt, phải nhờ vào sự hỗ trợ từ cộng đồng.
    - Thách thức về khả năng mở rộng, có thể đối mặt với các vấn đề về hiệu suất trong các triển khai quy mô lớn do những hạn chế về mặt tài nguyên.
- Nếu yêu cầu nhiều tính năng hơn và hỗ trợ cấp doanh nghiệp, người dùng có thể cân nhắc đến phần mềm DLP mã nguồn đóng (closed - source).

#### 2. OpenDLP:
- Miễn phí và mã nguồn mở.
- Tập trung vào việc quét dữ liệu đang ở trạng thái nghỉ.
- Hạn chế chính là khả năng mở rộng, điều này có thể được giải quyết bằng cách tích hợp nó với một hệ thống DLP nguồn đóng mạnh mẽ hơn để tăng cường hiệu suất và cải thiện các tính năng quản lý.

#### 3. Security Onion:
- Bản phân phối Linux miễn phí và mã nguồn mở, chủ yếu dành cho phát hiện xâm nhập, giám sát bảo mật mạng và quản lý nhật ký.
- Có thể được cấu hình cho các tác vụ DLP bằng cách tận dụng khả năng log mở rộng để giám sát và cảnh báo về các nỗ lực làm rò rỉ dữ liệu. Tuy nhiên vì nó không được thiết kế rõ ràng cho DLP nên nó chủ yếu giúp phát hiện các nguy cơ tiềm ẩn chứ không ngăn chặn chúng hoàn toàn.

#### 4. Snort:
- Hệ thống ngăn chặn xâm nhập mạng mã nguồn mở. Có thể thực hiện phân tích lưu lượng thời gian thực và khi log gói tin.
- Được cấu hình để thực hiện các tác vụ DLP, chẳng hạn như phát hiện thông tin nhận dạng cá nhân (PIL). Để cấu hình cho DLP, người dùng có thể viết các quy tắc tuỳ chỉnh nhằm phát hiện và cảnh báo về các mẫu dữ liệu cụ thể trong lưu lượng mạng cho thấy sự mất mát hoặc đánh cắp dữ liệu.

###
> *Do lĩnh vực DLP mã nguồn mở còn hạn chế nên các nguồn đã bao gồm thêm các phần mềm mã nguồn mở khác có thể đượ cấu hình để thực hiện các tác vụ DLP. Tuy nhiên việc này đòi hỏi phải tuỳ chỉnh và có chuyên môn đáng kể để đạt được hiệu quả như phần mềm DLP chuyên dụng. Sau đây là các phần mềm mã nguồn mở khác có thể cấu hình cho tác vụ DLP:*

#### 5. Wazuh:
- Mục đích chính: Chủ yếu là giải pháp Quản lý sự kiện và thông tin bảo mật (SIEM).
- Tính năng DLP: Cung cấp khả năng giám sát tính toàn vẹn của tệp, phát hiện lỗ hổng và quản lý rò rỉ dữ liệu thông qua khả năng ghi log và cảnh báo mở rộng.

#### 6. ModSecurity:
- Mục đích chính: Open-source web application firewall.
- Tính năng DLP: Có thể được cấu hình cho DLP bằng cách viết các quy tắc tuỳ chỉnh để phát hiện và chặn các mẫu dữ liệu nhạy cảm cụ thể trong lưu lượng HTTP.

#### 7. OSSEC:
- Mục đích chính: Công cụ bảo mật mã nguồn mở hoạt động như hệ thống phát hiện xâm nhập dựa trên máy chủ (HIDS).
- Tính năng DLP: Có thể giám sát các thay đổi trong tệp hoặc phát hiện rò rỉ dữ liệu nhạy cảm khi được cấu hình bằng các quy tắc tuỳ chỉnh.

#### 8. Pi-hole:
Chủ yếu là công cụ chặn quảng cáo và trình theo dõi ở cấp độ DNS nhưng nó có thể được điều chỉnh để lọc hoặc chặn các miền liên quan đến việc rò rỉ dữ liệu.

#### 9. ELK Stack (Elasticsearch, Logstash, Kibana):
- Mục đích chính: Là công cụ ghi log và trực quan hoá dữ liệu.
- Tính năng DLP: Nó có thể được điều chỉnh cho các tác vụ DLP thông qua các bảng điều khiển, truy vấn điều chỉnh và phát hiện các bất thường trong luồng dữ liệu.

#### 10. Nextcloud Anti-Virus (AV):
- Mục đích chính: Thực hiện quét virus, mối đe doạ và trojan tự động cho các tệp, nếu phát hiện sẽ cách ly tệp đó.
- Tính năng DLP: Để đảm bảo hiệu quả và tối ưu tính linh hoạt trong môi trường doanh nghiệp, Nextcloud đã tích hợp ICAP (Giao thức thích ứng nội dung Internet), vì vậy nó có thể được thiết lập để tương tác với nhiều ứng dụng DLP khác nhau và nhận hành động dựa trên thông tin bổ sung về các tệp.
    - AV có thể phát hiện và phân loại dữ liệu nhạy cảm và gắn tag nó.
    - Sau khi gắn tag, máy chủ có những hành động tương ứng.
    - Nextcloud nhận thấy rằng nhu cầu DLP của mỗi tổ chức là khác nhau nên họ cung cấp cách tiếp cận cá nhân hoá phù hợp với từng nhu cầu cụ thể.

### VI. So sánh với các giải pháp DLP thương mại:
OpenDLP là một giải pháp mạnh mẽ cho những ai tìm kiếm sự linh hoạt và tiết kiệm chi phí, đặc biệt là khi so sánh với các giải pháp thương mại:
<table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; text-align: left;">
  <thead style="background-color: #f2f2f2;">
    <tr>
      <th><b>Đặc điểm</b></th>
      <th><b>OpenDLP</b></th>
      <th><b>DLP Thương mại</b></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Chi phí</b></td>
      <td>Miễn phí tải xuống và sử dụng (GPL)</td>
      <td>Phí cấp phép và đăng ký cao</td>
    </tr>
    <tr>
      <td><b>Hỗ trợ</b></td>
      <td>Dựa trên cộng đồng vì không có công ty cung cấp dịch vụ chính thức</td>
      <td>Đội ngũ chuyên nghiệp tận tâm</td>
    </tr>
    <tr>
      <td><b>Khả năng Tùy chỉnh</b></td>
      <td>Cao, nhưng đòi hỏi chuyên môn</td>
      <td>Hạn chế nhưng đơn giản</td>
    </tr>
    <tr>
      <td><b>Tính năng</b></td>
      <td>Nền tảng với các tùy chọn tùy chỉnh</td>
      <td>Toàn diện và tích hợp (bao gồm endpoint, cloud)</td>
    </tr>
    <tr>
      <td><b>Phạm vi quét</b></td>
      <td>Thiết bị nội bộ (endpoint, file share)</td>
      <td>Toàn diện: endpoint, cloud, network, email, storage, v.v.</td>
    </tr>
    <tr>
      <td><b>Dễ sử dụng</b></td>
      <td>Ở mức vừa phải, cần thời gian học tập</td>
      <td>Thân thiện với người dùng, trực quan</td>
    </tr>
  </tbody>
</table>
