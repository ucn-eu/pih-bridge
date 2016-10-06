open Lwt

module Client = Cohttp_lwt_unix.Client


let green str = "\027[32m" ^ str ^ "\027[m"
let red   str = "\027[31m" ^ str ^ "\027[m"
let log_info str = Printf.printf "%s %s\n%!" (green "INFO:") str
let log_warn str = Printf.printf "%s %s\n%!" (red "WARN:") str


let insert uri lim =
  let ip = "10.0.0.1" in
  let dst_ip = "192.168.252.11" in
  let dst_port = 8443 in

  let body = Ezjsonm.(
    ["ip", string ip; "dst_ip", string dst_ip; "dst_port", int dst_port]
    |> dict
    |> to_string) in

  let rec insert_aux cnt =
    if cnt >= lim then return_unit
    else begin
        let body = Cohttp_lwt_body.of_string body in
        Client.post ~body uri >>= fun (resp, body) ->
        let status = Cohttp.Response.status resp in
        if status = `OK then begin
          log_info @@ Printf.sprintf "insert request NO. %d" cnt;
          insert_aux (succ cnt) end
        else
          Cohttp_lwt_body.to_string body >>= fun body ->
          log_warn @@ Printf.sprintf "status code: %s %s"
            (Cohttp.Code.string_of_status status) body;
          insert_aux (succ cnt)
      end
  in

  insert_aux 0


let main () =
  let endp = Sys.argv.(1) |> Uri.of_string in
  let uri = Uri.with_path endp "insert" in
  let lim = Sys.argv.(2) |> int_of_string in

  insert uri lim >>= fun () ->
  log_info @@ Printf.sprintf "%d to %s compelet" lim (Uri.to_string uri);
  return_unit


let () = Lwt_main.run (main ())
