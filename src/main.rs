#[tokio::main]
async fn main() {
    let image = "alpine:latest";
    let re = imageinfo::send_image(&image).await;
    println!("{:?}", re);
}
