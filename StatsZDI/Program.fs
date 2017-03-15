open System
open FSharp.Data
open FSharp.Control

open System.Collections.Generic


module Seq =
    let pmap f l =
        seq { for a in l -> f a }
        |> Async.Parallel
        |> Async.RunSynchronously

let StartingYear  = 2005

let AdvisoriesUrl = "http://www.zerodayinitiative.com/advisories/published/"
let AdvisoryUrl   = "http://www.zerodayinitiative.com/advisories/"

let PublishedToken = "Published: "
let CveToken       = "CVE: "

let titleKey      = "Title"
let cvssToken     = "CVSS Score"
let vendorsToken  = "Affected Vendors"
let productsToken = "Affected Products"

let mainContentDiv = "div#main-content"
let tableElement   = "table"
let titleElement   = "h2"
let trElement      = "tr"
let tdElement      = "td"


type Advisory = { ZID:      string;
                  CVEs:     string list;
                  Date:     DateTime;
                  Title:    string;
                  CVSS:     double;
                  Vendors:  string list;
                  Products: string list }

let getAdvisoriesUrl(year: int) : string =
    AdvisoriesUrl + string year + "/"

let getAdvisoryUrl(zid: string) : string =
    AdvisoryUrl + zid + "/"

let splitToList(chr: char, str: string) =
    str.Split([|chr|])
    |> Array.toList
    |> List.map(fun s -> s.Trim())
    |> List.filter(fun s -> s <> "")

let newlineToList(str: string) =
    splitToList('\n', str)

let commaToList(str: string) =
    splitToList(',', str)

let safeParseDouble(str: string) =
    match Double.TryParse str with
    | true, v -> v
    | _       -> 0.0

let safeParseDate(str: string) =
    match DateTime.TryParse str with
    | true, v -> v
    | _       -> new DateTime()

let safeGetValue(key: string, dictionary: IDictionary<string, string>) =
    match dictionary.TryGetValue key with
    | true, v -> v
    | _       -> ""

let extractTroika(troika: seq<HtmlNode>) =
    troika
    |> Seq.toList
    |> List.mapi(fun idx elm ->
                     let value = elm.InnerText()
                     match idx with
                     | 1 -> value.Replace(CveToken, "");
                     | 2 -> value.Replace(PublishedToken, "");
                     | _ -> value
    )

let getAdvisoryDetails(prv, elt: HtmlNode) =
    match (prv, elt) with
    | (Some(p: HtmlNode), e) -> 
        let heading = p.InnerText()
        if heading = cvssToken then
            let chunks = e.InnerText().Split([|','|])
            let score = Array.head chunks
            Some (heading, score)
        elif heading = vendorsToken ||
             heading = productsToken then
            let value = e.InnerText()
            Some (heading, value)
        else
            None
    | _ -> None


let fetchAdvisoryDetails(zid: string) = async {
    let url = getAdvisoryUrl zid
    let! detailsPage = HtmlDocument.AsyncLoad(url)

    let div = detailsPage.CssSelect(mainContentDiv)
              |> List.head

    let title = div.Descendants(titleElement)
                |> Seq.head
                |> HtmlNode.innerText

    let details = div.Elements()
                  |> List.mapFold(fun prv elt ->
                      (getAdvisoryDetails(prv, elt), Some elt)) None
                  |> fst
                  |> List.choose id

    return dict ((titleKey, title) :: details)
}

let filterTroikaTd(tr: HtmlNode) =
    let td = tr.Descendants tdElement
    match Seq.length td with
    | 3 -> Some (extractTroika td)
    | _ -> None

let getAdvisory(metadata: string list) = async {
    let zid = metadata.Item 0
    let cve = metadata.Item 1
    let date = metadata.Item 2
    let! details = fetchAdvisoryDetails zid
    let adv = { ZID = zid;
                CVEs = commaToList(cve);
                Date = safeParseDate(date);
                Title = safeGetValue(titleKey, details);
                CVSS = safeParseDouble(safeGetValue(cvssToken, details));
                Vendors = newlineToList(safeGetValue(vendorsToken, details));
                Products = newlineToList(safeGetValue(productsToken, details)) }

    printfn "%A" adv
    return adv
}

let getAdvisories(table: HtmlNode) =
    table.Descendants trElement
    |> Seq.choose(filterTroikaTd)
    |> Seq.pmap(getAdvisory)
   
let getFirstTable(doc: HtmlDocument) =
    Seq.head (doc.Descendants tableElement)
 
[<EntryPoint>]
let main argv =
    let currentYear = DateTime.Now.Year
    let years = [| StartingYear .. currentYear |]

    let advs = years
               |> Array.map(fun year ->
                      let url = getAdvisoriesUrl(year)
                      let results = HtmlDocument.Load(url)
                      let table = getFirstTable results
                      getAdvisories table)
               |> Array.concat

    let n = Array.length advs

    // TODO
    // Store `advs` in a DB

    printfn "Got %d advisories" n
    0