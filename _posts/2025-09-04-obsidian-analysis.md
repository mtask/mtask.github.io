---
title: 'Link analysis with Obsidian'
layout: 'post'
tags: ['cti', 'osint']
---
{:toc}

I’ve been experimenting with using Obsidian for investigation work such as OSINT cases or incident response. While it’s not a traditional link analysis tool like Maltego, with the right structure and plugins, Obsidian can be surprisingly effective.
Check [this](https://obsidian.md/) if you do not know what Obsidian is.

## Entities with templates


In Maltego, you work with entities like IP address or domain name that are placed onto a graph. In Obsidian, I replicate this by creating entity templates.
Here's an example template for an IP address:

```yaml
---
tag: ip
entity: ip
---
#anything else that you want to include#
```

A `domain` entity template might look like this:

```yaml
---
tag: domain
entity: domain
---
## DNS
<some details>
## WHOIS
<content>
```

The key part here is the `entity` field. The `tag` is less important for this workflow, though I usually set it to the same value for consistency and compatibility with other features.

If you’re looking for inspiration, you can find some example templates online by searching for “__Obsidian OSINT templates.__” I may publish my own at some point once they’re cleaned up and fine-tuned.

I keep all my entity templates in a dedicated folder. This is pretty much required, since Obsidian’s core Templates plugin (and the popular Templater plugin) assume that kind of structure. I also use the Iconize plugin to add icons to each entity type. That way, they show up nicely in the file navigator, like this:

![](/assets/IMG_4126.jpeg)

This can be done with templates by adding the `icon` entry to YAML frontmatter. For example:

```
icon: LiRouter
```

## Sample case

Let’s walk through a small sample case that mimics an investigation triggered by an IDS alert. Here’s the starting point:

```
[**] [1:2023456:3] ET POLICY Suspicious Outbound Connection to External Host [**]
[Classification: Potential Corporate Privacy Violation] [Priority: 2] 
04/12-14:36:45.892345 192.168.10.25:53214 -> 203.0.113.77:8080
TCP TTL:64 TOS:0x0 ID:39485 IpLen:20 DgmLen:60 DF
***AP*** Seq: 0x8A32D5F7  Ack: 0x3F2C91A4  Win: 0x16D0  TcpLen: 32
TCP Options (3) => NOP NOP TS: 134562738
```

### Preparation

One entity I like to use is of type `event`, which in this case represents the starting point for the investigation. Of course, more events can be added later as the case develops.
I create an event note from the alert by making a new note and applying the `event` template to it.


![](/assets/Pasted image 20250831110231.png)
![](/assets/Pasted image 20250831110258.png)

I’m using Templater plugin here because the event template contains Templater-specific syntax that automatically updates the filename. If you don’t need that kind of data manipulation during note creation, Obsidian’s core Templates plugin works just fine.
Here's how the note could look in Markdown.

```
---
entity: event
tags:
  - event
icon: LiClock
---
# Description

[**] [1:2023456:3] ET POLICY Suspicious Outbound Connection to External Host [**]
[Classification: Potential Corporate Privacy Violation] [Priority: 2] 
04/12-14:36:45.892345 192.168.10.25:53214 -> 203.0.113.77:8080
TCP TTL:64 TOS:0x0 ID:39485 IpLen:20 DgmLen:60 DF
***AP*** Seq: 0x8A32D5F7  Ack: 0x3F2C91A4  Win: 0x16D0  TcpLen: 32
TCP Options (3) => NOP NOP TS: 134562738


# Key Info

Host [[192.168.10.25]] made a suspicious connection to  [[203.0.113.77]]:8080.

# Analysis

TBD
```

Note `[[<ip>]]` syntax within the "Key Info" section. That creates a wikilink to another note. The link works even if the note doesn’t exist yet and note is autocreated when clicked.


### Data collection

Suppose we don’t yet know what asset is associated with the local IP. Clicking the link in the event note creates an empty note with the IP address as its title.

![](/assets/Pasted image 20250831105701.png)

Next we will apply the `ip` entity template to this note which populates us entity related information.

![](/assets/Pasted image 20250831105736.png)

As we collect information, we can add details to the note:

![](/assets/Pasted image 20250831105525.png)

Using Obsidian’s **Graph View**, we can quickly see how notes are connected:

![](/assets/Pasted image 20250831105859.png)

Grayed-out nodes in the graph represent linked notes that don’t exist yet. You can also group (color) nodes based on properties like tags.

![](/assets/Pasted image 20250831110020.png)


### Analyze with canvas

Now let’s take a look at the Canvas feature. Obsidian’s documentation describes it like this:

> Canvas allows you to organize notes visually — an infinite space to research, brainstorm, diagram and lay out your ideas.

This feature is quite neat, but sometimes you want some automation with it. By default you need to add everything manually. There are some plugins like [Link Exploder](https://github.com/benhughes/obsidian-link-exploder) that does help with this. There were some small things why none of the plugins worked for my usecase, so I decided to do some own scripting.

I'm not interested on creating an actual plugin at the moment and Obsidian stores all notes as markdown files on the filesystem so those can be manipulated directly without Obsidian. My approach is a Python script that does the following:

- Takes path to a note as an argument.
- All wikilinks are parsed from the note.
- These steps are repeated recursively until all the related notes are parsed.
- Creates a canvas file where notes are nodes and parsed wikilinks are edges (connections).
- Edges are auto labeled based on the entity of the linked note.

 For example, a note "foo" links to a note "bar" and "bar" has entity type of "domain". Here the script would populate connection `foo --domain--> bar`.

Let's take a look how canvas populated with the sample case data looks like. First we launch the script:

```shell
python3 .meta/canvas.py -f Cases/CaseSample/310820250047\ -\ IDS\ alert.md -o Cases/CaseSample/case.canvas
```

Now we can open the "case.canvas" inside Obsidian.

![](/assets/Pasted image 20250831112228.png)

Moving the nodes makes is it a bit easier to see the connections.

![](/assets/Pasted image 20250831112405.png)

From here we can add information directly to the canvas.  In addition to notes you can directly insert, for example, images or just text boxes.

![](/assets/Pasted image 20250831113009.png)

Here's the `canvas.py` script: 

{% gist 86cf48a3b80a5ff93096bc72f730e9c8 %}

## Other considerations

### De-cluttering

Instead of separate `ip` and `domain` entities, you might use a more general `host` entity to cover both. This reduces the total number of notes and can make your canvas less cluttered.
Obsidian also has a built-in alias feature that comes in handy. For example, suppose you have an `email` entity for `john.doe@example.com` linked to the `person` entity John Doe. Later, you discover another email, `john.doe@domain.local`. You can add it as an alias in the existing email note’s frontmatter like this:

```yaml
alias: john.doe@domain.local
```

The downside is that aliases don’t show up in Graph or Canvas views. Whether that’s an issue depends on your workflow.

### Duplicate information

When writing content for each entity, it’s easy to accidentally duplicate information across multiple notes. If you just want to reference an entity, keep it simple: add a wikilink like `[[some entity]]` to an otherwise empty note and move on.

### Integrating the canvas script

There are plugins that allow command execution from within Obsidian. Using one of these, the canvas generation script could potentially be integrated directly into your workflow.

### Naming limitations

Sometimes it could be useful to have `:` in the note title. For example, with ip-port number combination. In the example case we could have had a note `203.0.113.77:8080` instead of `203.0.113.77`. Here some own naming schema is need like using just dash `203.0.113.77-8080-tcp`.
