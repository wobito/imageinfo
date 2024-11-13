#[tokio::main]
async fn main() {
    let image = "alpine:latest";
    let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let re = imageinfo::send_image_info(&image, &digest).await;
    println!("{:?}", re);
}
