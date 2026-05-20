package config;

import burp.api.montoya.persistence.Persistence;

public class Config {
    private String nucleiPath = "";
    private String templatesPath = "";
    private final Persistence persistence;

    public Config(Persistence persistence) {
        this.persistence = persistence;
        load();
    }

    private void load() {
        String savedNucleiPath = persistence.extensionData().getString("nucleiPath");
        if (savedNucleiPath != null) this.nucleiPath = savedNucleiPath;

        String savedTemplatesPath = persistence.extensionData().getString("templatesPath");
        if (savedTemplatesPath != null) this.templatesPath = savedTemplatesPath;
    }

    public void save() {
        persistence.extensionData().setString("nucleiPath", nucleiPath);
        persistence.extensionData().setString("templatesPath", templatesPath);
    }

    public String getNucleiPath() {
        return nucleiPath;
    }

    public void setNucleiPath(String nucleiPath) {
        this.nucleiPath = nucleiPath;
        save();
    }

    public String getTemplatesPath() {
        return templatesPath;
    }

    public void setTemplatesPath(String templatesPath) {
        this.templatesPath = templatesPath;
        save();
    }
}
